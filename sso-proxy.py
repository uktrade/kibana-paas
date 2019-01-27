import asyncio
import contextlib
import itertools
import json
import logging
import os
import secrets
import string
import sys
import urllib

import aiohttp
from aiohttp import web
from aiohttp_session import (
    get_session,
    session_middleware,
)
from aiohttp_session.redis_storage import RedisStorage
import aioredis
from yarl import (
    URL,
)


INCORRECT = 'Incorrect authentication credentials.'


async def run_application():
    logger = get_root_logger('elasticsearch-proxy')

    with logged(logger, 'Examining environment', []):
        env = normalise_environment(os.environ)
        port = env['PORT']
        ip_whitelist = env['INCOMING_IP_WHITELIST']
        staff_sso_client_base = env['STAFF_SSO_BASE']
        staff_sso_client_id = env['STAFF_SSO_CLIENT_ID']
        staff_sso_client_secret = env['STAFF_SSO_CLIENT_SECRET']
        kibana_url_no_password = URL('http://127.0.0.1:5601')

        vcap_services = json.loads(env['VCAP_SERVICES'])
        es_uri = vcap_services['elasticsearch'][0]['credentials']['uri']
        redis_uri = vcap_services['redis'][0]['credentials']['uri']

        es_parsed = URL(es_uri)
        es_user = es_parsed.user
        es_password = es_parsed.password
        kibana_url = kibana_url_no_password.with_user(es_user).with_password(es_password)

    client_session = aiohttp.ClientSession(skip_auto_headers=['Accept-Encoding'])

    async def handle(request):
        url = kibana_url.with_path(request.url.path)
        request_body = await request.read()
        headers = {
            header: request.headers[header]
            for header in ['Kbn-Version', 'Content-Type']
            if header in request.headers
        }

        with logged(
            request['logger'], 'Elasticsearch request by (%s) to (%s) (%s) (%s) (%s)', [
                request['me_profile']['email'],
                request.method, str(url), request.url.query, request_body,
            ],
        ):
            async with client_session.request(
                request.method, str(url), params=request.url.query, data=request_body,
                headers=headers,
            ) as response:
                response_body = await response.read()
        response_headers = {
            key: value for key, value in response.headers.items()
            if key != 'Transfer-Encoding'
        }
        return web.Response(status=response.status, body=response_body, headers=response_headers)

    redis_pool = await aioredis.create_pool(redis_uri)
    redis_storage = RedisStorage(redis_pool, max_age=60*60*24)

    with logged(logger, 'Creating listening web application', []):
        app = web.Application(middlewares=[
            server_logger(logger),
            authenticate_by_ip(INCORRECT, ip_whitelist),
            session_middleware(redis_storage),
            authenticate_by_staff_sso(client_session, staff_sso_client_base,
                                      staff_sso_client_id, staff_sso_client_secret),
        ])

        app.add_routes([
            web.delete(r'/{path:.*}', handle),
            web.get(r'/{path:.*}', handle),
            web.post(r'/{path:.*}', handle),
            web.put(r'/{path:.*}', handle),
            web.head(r'/{path:.*}', handle),
        ])

        class NullAccessLogger(aiohttp.abc.AbstractAccessLogger):
            # pylint: disable=too-few-public-methods

            def log(self, request, response, time):
                pass

        runner = web.AppRunner(app, access_log_class=NullAccessLogger)
        await runner.setup()
        site = web.TCPSite(runner, '0.0.0.0', port)
        await site.start()


def authenticate_by_staff_sso(client_session, base, client_id, client_secret):

    auth_path = '/o/authorize/'
    token_path = '/o/token/'
    me_path = '/api/v1/user/me/'
    grant_type = 'authorization_code'
    scope = 'read write'
    response_type = 'code'

    redirect_from_sso_path = '/__redirect_from_sso'
    session_token_key = 'staff_sso_access_token'

    def get_redirect_uri_authenticate(session, request):
        state = secrets.token_urlsafe(32)
        set_redirect_uri_final(session, state, request)
        redirect_uri_callback = urllib.parse.quote(get_redirect_uri_callback(request), safe='')
        return f'{base}{auth_path}?' \
               f'scope={scope}&state={state}&' \
               f'redirect_uri={redirect_uri_callback}&' \
               f'response_type={response_type}&' \
               f'client_id={client_id}'

    def get_redirect_uri_callback(request):
        uri = request.url.with_scheme(request.headers['X-Forwarded-Proto']) \
                         .with_path(redirect_from_sso_path) \
                         .with_query({})
        return str(uri)

    def set_redirect_uri_final(session, state, request):
        session[state] = str(request.url)

    def get_redirect_uri_final(session, request):
        state = request.query['state']
        return session[state]

    @web.middleware
    async def _authenticate_by_sso(request, handler):
        session = await get_session(request)

        if request.path != redirect_from_sso_path and session_token_key not in session:
            return web.Response(status=302, headers={
                'Location': get_redirect_uri_authenticate(session, request),
            })

        if request.path == redirect_from_sso_path:
            code = request.query['code']
            redirect_uri_final = get_redirect_uri_final(session, request)
            sso_response = await client_session.post(
                f'{base}{token_path}',
                data={
                    'grant_type': grant_type,
                    'code': code,
                    'client_id': client_id,
                    'client_secret': client_secret,
                    'redirect_uri': get_redirect_uri_callback(request),
                },
            )
            session[session_token_key] = (await sso_response.json())['access_token']
            return web.Response(status=302, headers={'Location': redirect_uri_final})

        token = session[session_token_key]
        async with client_session.get(f'{base}{me_path}', headers={
            'Authorization': f'Bearer {token}'
        }) as me_response:
            me_profile = await me_response.json()

        request['me_profile'] = me_profile
        return \
            await handler(request) if me_response.status == 200 else \
            web.Response(status=302, headers={
                'Location': get_redirect_uri_authenticate(session, request),
            })

    return _authenticate_by_sso


## Logging

class ContextAdapter(logging.LoggerAdapter):
    def process(self, msg, kwargs):
        return '[%s] %s' % (','.join(self.extra['context']), msg), kwargs


def get_root_logger(context):
    logger = logging.getLogger('sso-proxy')
    return ContextAdapter(logger, {'context': [context]})


def get_child_logger(logger, child_context):
    existing_context = logger.extra['context']
    return ContextAdapter(logger.logger, {'context': existing_context + [child_context]})


@contextlib.contextmanager
def logged(logger, message, logger_args):
    try:
        logger.debug(message + '...', *logger_args)
        status = 'done'
        logger_func = logger.debug
        yield
    except asyncio.CancelledError:
        status = 'cancelled'
        logger_func = logger.debug
        raise
    except BaseException:
        status = 'failed'
        logger_func = logger.warning
        raise
    finally:
        logger_func(message + '... (%s)', *(logger_args + [status]))


def server_logger(logger):

    def random_url_safe(count):
        return ''.join(secrets.choice(string.ascii_lowercase + string.digits) for _ in range(count))

    @web.middleware
    async def _server_logger(request, handler):
        child_logger = get_child_logger(logger, random_url_safe(8))
        request['logger'] = child_logger
        child_logger.debug('Receiving request (%s) (%s %s HTTP/%s.%s) (%s) (%s)', *(
            (
                request.remote,
                request.method,
                request.path_qs,
            ) +
            request.version +
            (
                request.headers.get('User-Agent', '-'),
                request.headers.get('X-Forwarded-For', '-'),
            )
        ))

        with logged(child_logger, 'Processing request', []):
            response = await handler(request)

        child_logger.debug(
            'Sending Response (%s) (%s)',
            response.status, response.content_length,
        )

        return response

    return _server_logger


## IP filtering

def authenticate_by_ip(incorrect, ip_whitelist):

    @web.middleware
    async def _authenticate_by_ip(request, handler):
        if 'X-Forwarded-For' not in request.headers:
            request['logger'].warning(
                'Failed authentication: no X-Forwarded-For header passed'
            )
            raise web.HTTPUnauthorized(text=incorrect)

        # PaaS appends 2 IPs, where the IP connected from is the first of the two
        ip_addesses = request.headers['X-Forwarded-For'].split(',')
        if len(ip_addesses) < 2:
            request['logger'].warning(
                'Failed authentication: the X-Forwarded-For header does not '
                'contain enough IP addresses'
            )
            raise web.HTTPUnauthorized(text=incorrect)

        remote_address = ip_addesses[-2].strip()

        if remote_address not in ip_whitelist:
            request['logger'].warning(
                'Failed authentication: the IP address derived from the '
                'X-Forwarded-For header is not in the whitelist'
            )
            raise web.HTTPUnauthorized(text=incorrect)

        return await handler(request)

    return _authenticate_by_ip


## Environment

def normalise_environment(key_values):
    ''' Converts denormalised dict of (string -> string) pairs, where the first string
        is treated as a path into a nested list/dictionary structure

        {
            "FOO__1__BAR": "setting-1",
            "FOO__1__BAZ": "setting-2",
            "FOO__2__FOO": "setting-3",
            "FOO__2__BAR": "setting-4",
            "FIZZ": "setting-5",
        }

        to the nested structure that this represents

        {
            "FOO": [{
                "BAR": "setting-1",
                "BAZ": "setting-2",
            }, {
                "BAR": "setting-3",
                "BAZ": "setting-4",
            }],
            "FIZZ": "setting-5",
        }

        If all the keys for that level parse as integers, then it's treated as a list
        with the actual keys only used for sorting

        This function is recursive, but it would be extremely difficult to hit a stack
        limit, and this function would typically by called once at the start of a
        program, so efficiency isn't too much of a concern.
    '''

    # Separator is chosen to
    # - show the structure of variables fairly easily;
    # - avoid problems, since underscores are usual in environment variables
    separator = '__'

    def get_first_component(key):
        return key.split(separator)[0]

    def get_later_components(key):
        return separator.join(key.split(separator)[1:])

    without_more_components = {
        key: value
        for key, value in key_values.items()
        if not get_later_components(key)
    }

    with_more_components = {
        key: value
        for key, value in key_values.items()
        if get_later_components(key)
    }

    def grouped_by_first_component(items):
        def by_first_component(item):
            return get_first_component(item[0])

        # groupby requires the items to be sorted by the grouping key
        return itertools.groupby(
            sorted(items, key=by_first_component),
            by_first_component,
        )

    def items_with_first_component(items, first_component):
        return {
            get_later_components(key): value
            for key, value in items
            if get_first_component(key) == first_component
        }

    nested_structured_dict = {
        **without_more_components, **{
            first_component: normalise_environment(
                items_with_first_component(items, first_component))
            for first_component, items in grouped_by_first_component(with_more_components.items())
        }}

    def all_keys_are_ints():
        def is_int(string_to_test):
            try:
                int(string_to_test)
                return True
            except ValueError:
                return False

        return all([is_int(key) for key, value in nested_structured_dict.items()])

    def list_sorted_by_int_key():
        return [
            value
            for key, value in sorted(
                nested_structured_dict.items(),
                key=lambda key_value: int(key_value[0])
            )
        ]

    return \
        list_sorted_by_int_key() if all_keys_are_ints() else \
        nested_structured_dict



def main():
    stdout_handler = logging.StreamHandler(sys.stdout)
    app_logger = logging.getLogger('sso-proxy')
    app_logger.setLevel(logging.DEBUG)
    app_logger.addHandler(stdout_handler)

    loop = asyncio.get_event_loop()
    loop.create_task(run_application())
    loop.run_forever()


if __name__ == '__main__':
    main()
