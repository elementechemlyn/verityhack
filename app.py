__copyright__ = 'COPYRIGHT 2013-2019, ALL RIGHTS RESERVED, EVERNYM INC.'

import asyncio
import logging
import os
import pyqrcode
import requests
import traceback
from aiohttp import web
from aiohttp.web_routedef import RouteTableDef
from asyncio.base_events import Server
from example.helper import *
from verity_sdk.handlers import Handlers
from verity_sdk.protocols.v0_6.IssuerSetup import IssuerSetup
from verity_sdk.protocols.v0_6.UpdateConfigs import UpdateConfigs
from verity_sdk.protocols.v0_6.UpdateEndpoint import UpdateEndpoint
from verity_sdk.protocols.v0_6.WriteCredentialDefinition import WriteCredentialDefinition
from verity_sdk.protocols.v0_6.WriteSchema import WriteSchema
from verity_sdk.protocols.v0_7.Provision import Provision
from verity_sdk.protocols.v1_0.Connecting import Connecting
from verity_sdk.protocols.v1_0.IssueCredential import IssueCredential
from verity_sdk.protocols.v1_0.PresentProof import PresentProof
from verity_sdk.protocols.v1_0.Relationship import Relationship
from verity_sdk.protocols.v1_0.OutOfBand import OutOfBand
from verity_sdk.utils.Context import Context

import aiohttp_session 
import aiohttp_session.cookie_storage as cookie_storage
import aiohttp_jinja2
import jinja2

INSTITUTION_NAME = 'Faber College'
LOGO_URL = 'http://robohash.org/235'

SCHEMA_ID = "UMNNKgnk8cF4mxGjzNGq1A:2:Medication:896.476.774"
CRED_DEF_ID = "UMNNKgnk8cF4mxGjzNGq1A:3:CL:144237:latest"

context: Context
issuer_did: str = ''
issuer_verkey: str = ''

server: Server
port: int = 4000
handlers: Handlers = Handlers()
handlers.set_default_handler(default_handler)
handlers.add_handler('trust_ping', '1.0', noop)

routes: RouteTableDef = web.RouteTableDef()


async def create_relationship(loop) -> str:
    global context
    global handlers

    # Relationship protocol has two steps
    # 1. create relationship key
    # 2. create invitation

    # Constructor for the Relationship API
    relationship: Relationship = Relationship(label='inviter')
    rel_did = loop.create_future()
    thread_id = loop.create_future()

    spinner = make_spinner('Waiting to create relationship')  # Console spinner

    # handler for the response to the request to start the Connecting protocol.
    async def created_handler(msg_name, message):
        spinner.stop_and_persist('Done')
        print_message(msg_name, message)
        if msg_name == Relationship.CREATED:
            thread_id.set_result(message['~thread']['thid'])
            rel_did.set_result(message['did'])
        else:
            non_handled(f'Message name is not handled - {msg_name}', message)

    # adds handler to the set of handlers
    handlers.add_handler(Relationship.MSG_FAMILY, Relationship.MSG_FAMILY_VERSION, created_handler)

    spinner.start()

    # starts the relationship protocol
    await relationship.create(context)
    thread_id = await thread_id
    rel_did = await rel_did

    # Step 2
    invitation = loop.create_future()

    spinner = make_spinner('Waiting to create invitation')  # Console spinner

    # handler for the accept message sent when invitation is created
    async def invitation_handler(msg_name, message):
        spinner.stop_and_persist('Done')
        print_message(msg_name, message)
        if msg_name == Relationship.INVITATION:
            invite_url = message["inviteURL"]
            # write QRCode to disk
            qr = pyqrcode.create(invite_url)
            qr.png('static/qrcode.png')

            if os.environ.get("HTTP_SERVER_URL"):
                print('Open the following URL in your browser and scan presented QR code')
                print(f'{ANSII_GREEN}{os.environ.get("HTTP_SERVER_URL")}/python-example-app/qrcode.html{ANSII_RESET}')
            else:
                print('QR code generated at: qrcode.png')
                print('Open this file and scan QR code to establish a connection')
            invitation.set_result(None)
        else:
            non_handled(f'Message name is not handled - {msg_name}', message)

    spinner.start()
    # note this overrides the handler for this message family! This is for demonstration purposes only.
    handlers.add_handler(Relationship.MSG_FAMILY, Relationship.MSG_FAMILY_VERSION, invitation_handler)

    relationship: Relationship = Relationship(rel_did, thread_id)
    await relationship.connection_invitation(context)
    await invitation
    return rel_did  # return owning DID for the connection


async def create_connection(loop):
    global context
    global handlers

    # Connecting protocol has two steps
    # 1. Wait for connection request
    # 2. Send connection response (connected)

    # Step 1

    request_received = loop.create_future()

    spinner = make_spinner('Waiting to start connection')  # Console spinner

    # handler for the response to the request to start the Connecting protocol.
    async def inviter_handler(msg_name, message):
        spinner.stop_and_persist('Done')
        print_message(msg_name, message)
        if msg_name == Connecting.REQUEST_RECEIVED:
            request_received.set_result(None)
        else:
            non_handled(f'Message name is not handled - {msg_name}', message)

    # adds handler to the set of handlers
    handlers.add_handler(Connecting.MSG_FAMILY, Connecting.MSG_FAMILY_VERSION, inviter_handler)

    spinner.start()

    # waits for request
    await request_received  # wait for response from verity application

    # Step 2
    connected = loop.create_future()
    spinner = make_spinner('Waiting to respond to connection')  # Console spinner

    # handler for the accept message sent when connection is accepted
    async def connection_response_handler(msg_name, message):
        spinner.stop_and_persist('Done')
        print_message(msg_name, message)
        if msg_name == Connecting.RESPONSE_SENT:
            connected.set_result(None)
        else:
            non_handled(f'Message name is not handled - {msg_name}', message)

    spinner.start()
    # note this overrides the handler for this message family! This is for demonstration purposes only.
    handlers.add_handler(Connecting.MSG_FAMILY, Connecting.MSG_FAMILY_VERSION, connection_response_handler)

    await connected  # wait for acceptance from connect.me user


async def write_ledger_schema(loop) -> str:
    # input parameters for schema
    schema_name = 'Medication'
    schema_version = get_random_version()
    schema_attrs = ['Medication Snomed', 'Medication Display', 
                    'Repeat Frequency','Repeat Period','Repeat Unit',
                    'Route Snomed','Route Display',
                    'Dose Quantity','Dose Unit' , 'PODS URL']

    # constructor for the Write Schema protocol
    schema = WriteSchema(schema_name, schema_version, schema_attrs)

    first_step = loop.create_future()

    spinner = make_spinner('Waiting to write schema to ledger')  # Console spinner

    # handler for message received when schema is written
    async def schema_written_handler(msg_name, message):
        spinner.stop_and_persist('Done')
        print_message(msg_name, message)
        if msg_name == WriteSchema.STATUS:
            first_step.set_result(message['schemaId'])
        else:
            non_handled(f'Message name is not handled - {msg_name}', message)

    # adds handler to the set of handlers
    handlers.add_handler(WriteSchema.MSG_FAMILY, WriteSchema.MSG_FAMILY_VERSION, schema_written_handler)

    spinner.start()

    # request schema be written to ledger
    await schema.write(context)
    schema_id = await first_step  # wait for operation to be complete
    return schema_id  # returns ledger schema identifier


async def write_ledger_cred_def(loop, schema_id: str) -> str:
    # input parameters for cred definition
    cred_def_name = 'Some Prescribing Org'
    cred_def_tag = 'latest'

    # constructor for the Write Credential Definition protocol
    cred_def = WriteCredentialDefinition(cred_def_name, schema_id, cred_def_tag)

    first_step = loop.create_future()

    spinner = make_spinner('Waiting to write cred def to ledger')  # Console spinner

    # handler for message received when schema is written
    async def cred_def_written_handler(msg_name, message):
        spinner.stop_and_persist('Done')
        print_message(msg_name, message)
        if msg_name == WriteCredentialDefinition.STATUS:
            first_step.set_result(message['credDefId'])
        else:
            non_handled(f'Message name is not handled - {msg_name}', message)

    # adds handler to the set of handlers
    handlers.add_handler(
        WriteCredentialDefinition.MSG_FAMILY,
        WriteCredentialDefinition.MSG_FAMILY_VERSION,
        cred_def_written_handler
    )

    spinner.start()

    # request the cred def be writen to ledger
    await cred_def.write(context)
    cred_def_id = await first_step  # wait for operation to be complete
    return cred_def_id  # returns ledger cred def identifier

async def issue_credential(loop, rel_did, cred_def_id,cred_data=None):
    # input parameters for issue credential
    credential_name = 'Medication'
    if cred_data == None:
        credential_data = {'Medication Snomed':'324095003',
                            'Medication Display':'Oxytetracycline 250mg tablets', 
                            'Repeat Frequency':'1',
                            'Repeat Period':'6',
                            'Repeat Unit':'h',
                            'Route Snomed':'26643006',
                            'Route Display':'Oral',
                            'Dose Quantity':'1',
                            'Dose Unit':'Tablet',
                            'PODS URL':'some.url'}
    else:
        credential_data = cred_data
    # constructor for the Issue Credential protocol
    issue = IssueCredential(rel_did, None, cred_def_id, credential_data, "Vaccination Confirmation", 0, True)

    offer_sent = loop.create_future()
    cred_sent = loop.create_future()
    spinner = make_spinner('Wait for Connect.me to accept the Credential Offer')  # Console spinner

    # handler for 'sent` message when the offer for credential is sent
    async def send_offer_handler(msg_name, message):
        spinner.stop_and_persist('Done')
        print_message(msg_name, message)
        if msg_name == IssueCredential.SENT:
            offer_sent.set_result(None)
        else:
            non_handled(f'Message name is not handled - {msg_name}', message)

    # adds handler to the set of handlers
    handlers.add_handler(IssueCredential.MSG_FAMILY, IssueCredential.MSG_FAMILY_VERSION, send_offer_handler)

    spinner.start()
    # request that credential is offered
    await issue.offer_credential(context)
    await offer_sent  # wait for sending of offer to connect.me user

    # handler for 'sent` message when the credential is sent
    async def send_cred_handler(msg_name, message):
        spinner.stop_and_persist('Done')
        print_message(msg_name, message)
        if msg_name == IssueCredential.SENT:
            cred_sent.set_result(None)
        else:
            non_handled(f'Message name is not handled - {msg_name}', message)

    # adds handler to the set of handlers
    handlers.add_handler(IssueCredential.MSG_FAMILY, IssueCredential.MSG_FAMILY_VERSION, send_cred_handler)

    spinner = make_spinner('waiting to send credential')  # Console spinner
    spinner.start()
    handlers.add_handler(IssueCredential.MSG_FAMILY, IssueCredential.MSG_FAMILY_VERSION, send_cred_handler)
    await cred_sent
    await asyncio.sleep(3)  # Wait a few seconds for the credential to arrive before sending the proof


async def request_proof(loop, for_did):
    global issuer_did

    # input parameters for request proof
    proof_name = 'Medication List'
    proof_attrs = [
        {
            'name': 'Medication Snomed',
            'restrictions': [{'issuer_did': issuer_did}]
        },
        {
            'name': 'Medication Display',
            'restrictions': [{'issuer_did': issuer_did}]
        },
        {
            'name': 'Repeat Frequency',
            'restrictions': [{'issuer_did': issuer_did}]
        },
        {
            'name': 'Repeat Period',
            'restrictions': [{'issuer_did': issuer_did}]
        },
        {
            'name': 'Repeat Unit',
            'restrictions': [{'issuer_did': issuer_did}]
        },
        {
            'name': 'Route Snomed',
            'restrictions': [{'issuer_did': issuer_did}]
        },
        {
            'name': 'Route Display',
            'restrictions': [{'issuer_did': issuer_did}]
        },
        {
            'name': 'Dose Quantity',
            'restrictions': [{'issuer_did': issuer_did}]
        },
        {
            'name': 'Dose Unit',
            'restrictions': [{'issuer_did': issuer_did}]
        },
        {
            'name': 'PODS URL',
            'restrictions': [{'issuer_did': issuer_did}]
        },
    ]

    # constructor for the Present Proof protocol
    proof = PresentProof(for_did, None, proof_name, proof_attrs)

    spinner = make_spinner('Waiting for proof presentation from Connect.me')  # Console spinner
    first_step = loop.create_future()

    # handler for the result of the proof presentation
    async def proof_handler(msg_name, message):
        spinner.stop_and_persist('Done')
        print_message(msg_name, message)
        if msg_name == PresentProof.PRESENTATION_RESULT:
            first_step.set_result(message)  # proof data contained inside `message`
        else:
            non_handled(f'Message name is not handled - {msg_name}', message)

    # adds handler to the set of handlers
    handlers.add_handler(PresentProof.MSG_FAMILY, PresentProof.MSG_FAMILY_VERSION, proof_handler)

    spinner.start()

    # request proof
    await proof.request(context)
    message = await first_step  # wait for connect.me user to present the requested proof
    return message

async def setup(loop):
    global context
    global issuer_did

    # look for context on disk
    config = load_context('verity-context.json')
    if config:
        context = await Context.create_with_config(config)
    else:
        context = await provision_agent()

    with open('verity-context.json', 'w') as f:
        f.write(context.to_json())

    await update_webhook_endpoint()

    print_object(context.to_json(indent=2), '>>>', 'Context Used:')

    with open('verity-context.json', 'w') as f:
        f.write(context.to_json())

    await update_configs()

    await issuer_identifier(loop)

    if not issuer_did:
        await setup_issuer(loop)


async def provision_agent() -> str:
    global context
    wallet_name = 'examplewallet1'  # for libindy wallet
    wallet_key = 'examplewallet1'
    token = None
    if console_yes_no("Provide Provision Token", True):
        token = console_input("Token", os.environ.get("TOKEN"))
        print(f'Using provision token: {ANSII_GREEN}{token}{ANSII_RESET}')

    verity_url = console_input(f'Verity Application Endpoint', os.environ.get("VERITY_SERVER"))
    print(f'Using Verity Application Endpoint Url: {ANSII_GREEN}{verity_url}{ANSII_RESET}')
    # create initial Context
    context = await Context.create(wallet_name, wallet_key, verity_url)

    # ask that an agent by provision (setup) and associated with created key pair
    try:
        response = await Provision(token).provision(context)
        return response
    except Exception as e:
        print(e)
        print("Provisioning failed! Likely causes:")
        print("- token not provided but Verity Endpoint requires it")
        print("- token provided but is invalid or expired")
        sys.exit(1)


async def update_webhook_endpoint():
    global context, port
    webhook_from_ctx: str = context.endpoint_url

    if not webhook_from_ctx:
        # Default to localhost on the default port
        webhook_from_ctx = f'http://localhost:{port}'

    webhook: str = console_input(f'Ngrok endpoint [{webhook_from_ctx}]', os.environ.get("WEBHOOK_URL"))

    if not webhook:
        webhook = webhook_from_ctx

    print(f'Using Webhook: {ANSII_GREEN}{webhook}{ANSII_RESET}')
    print()
    context.endpoint_url = webhook

    # request that verity application use specified webhook endpoint
    await UpdateEndpoint().update(context)


async def update_configs():
    handlers.add_handler('update-configs', '0.6', noop)
    configs = UpdateConfigs(INSTITUTION_NAME, LOGO_URL)
    await configs.update(context)


async def issuer_identifier(loop):
    # constructor for the Issuer Setup protocol
    issuer_setup = IssuerSetup()

    first_step = loop.create_future()

    spinner = make_spinner('Waiting for current issuer DID')  # Console spinner

    # handler for current issuer identifier message
    async def current_identifier(msg_name, message):
        global issuer_did
        global issuer_verkey

        spinner.stop_and_persist('Done')

        if msg_name == IssuerSetup.PUBLIC_IDENTIFIER:
            issuer_did = message['did']
            issuer_verkey = message['verKey']
            first_step.set_result(None)
        elif msg_name == IssuerSetup.PROBLEM_REPORT:
            # Do nothing. Just means we need to write the keys to the ledger. Checked for in setup()
            first_step.set_result(None)
        else:
            non_handled(f'Message name is not handled - {msg_name}', message)

    # adds handler to the set of handlers
    handlers.add_handler(IssuerSetup.MSG_FAMILY, IssuerSetup.MSG_FAMILY_VERSION, current_identifier)

    spinner.start()

    # query the current identifier
    await issuer_setup.current_public_identifier(context)
    await first_step  # wait for response from verity application


async def setup_issuer(loop):
    # constructor for the Issuer Setup protocol
    issuer_setup = IssuerSetup()

    first_step = loop.create_future()

    spinner = make_spinner('Waiting for setup to complete')  # Console spinner

    # handler for created issuer identifier message
    async def public_identifier_handler(msg_name, message):
        global issuer_did
        global issuer_verkey

        spinner.stop_and_persist('Done')

        if msg_name == IssuerSetup.PUBLIC_IDENTIFIER_CREATED:
            issuer_did = message['identifier']['did']
            issuer_verkey = message['identifier']['verKey']
            print('The issuer DID and Verkey must be registered on the ledger.')
            automated_registration = console_yes_no('Attempt automated registration via https://selfserve.sovrin.org', True)
            if automated_registration:
                url = 'https://selfserve.sovrin.org/nym'
                payload = json.dumps({
                            'network': 'stagingnet',
                            'did': issuer_did,
                            'verkey': issuer_verkey,
                            'paymentaddr': ''
                        })
                headers = {'Accept': 'application/json'}
                response = requests.request("POST", url, headers=headers, data=payload)
                if response.status_code != 200:
                    print('Something went wrong with contactig Sovrin portal')
                    print(f'Please add DID ({issuer_did}) and Verkey ({issuer_verkey}) to ledger manually')
                    console_input('Press ENTER when DID is on ledger')
                else:
                    print(f'Got response from Sovrin portal: {ANSII_GREEN}{response.text}{ANSII_RESET}')
            else:
                print(f'Please add DID ({issuer_did}) and Verkey ({issuer_verkey}) to ledger manually')
                console_input('Press ENTER when DID is on ledger')
            first_step.set_result(None)
        else:
            non_handled(f'Message name is not handled - {msg_name}')

    # adds handler to the set of handlers
    handlers.add_handler(IssuerSetup.MSG_FAMILY, IssuerSetup.MSG_FAMILY_VERSION, public_identifier_handler)

    spinner.start()

    # request that issuer identifier be created
    await issuer_setup.create(context)

    await first_step  # wait for request to complete

@routes.get('/')
async def index(request):
    raise web.HTTPFound('/static/index.html')

@routes.get('/connect')
async def index(request):
    loop = asyncio.get_event_loop()
    rel_did = await create_relationship(loop)
    session = await aiohttp_session.get_session(request)
    session['rel_did'] = rel_did
    raise web.HTTPFound('/static/qrcode.html')

@routes.get('/completeconnect')
async def completeconnect(request):
    loop = asyncio.get_event_loop()
    await create_connection(loop)
    raise web.HTTPFound('/static/connectioncomplete.html')

@routes.get('/prescribe')
async def prescribe(request):
    raise web.HTTPFound('/static/prescribe.html')

@routes.post('/issue')
async def issue(request):
    loop = asyncio.get_event_loop()
    # TODO - Store this so we don't need to keep remaking it?
    schema_id = SCHEMA_ID
    #await write_ledger_schema(loop)

    # TODO - Store this so we don't need to keep remaking it?
    cred_def_id = CRED_DEF_ID
    #await write_ledger_cred_def(loop, schema_id)

    post_data = await request.post()
    session = await aiohttp_session.get_session(request)
    rel_did = session['rel_did']
    cred_data = {'Medication Snomed':post_data["medsnomed"],
                    'Medication Display':post_data["meddisplay"], 
                    'Repeat Frequency':post_data["repfreq"],
                    'Repeat Period':post_data["repperiod"],
                    'Repeat Unit':post_data["repunit"],
                    'Route Snomed':post_data["routesnomed"],
                    'Route Display':post_data["routedisplay"],
                    'Dose Quantity':post_data["dosequantity"],
                    'Dose Unit':post_data["doseunit"],
                    'PODS URL':post_data["podsurl"] }

    await issue_credential(loop, rel_did, cred_def_id, cred_data)
    raise web.HTTPFound('/static/prescribed.html')

@routes.get('/request')
async def index(request):
    loop = asyncio.get_event_loop()
    session = await aiohttp_session.get_session(request)
    rel_did = session['rel_did']
    data = await request_proof(loop,rel_did)
    response = aiohttp_jinja2.render_template('review.jinja2',
                                            request,
                                            data)

    return response #web.Response(text="%s" % response)

@routes.get('/revoke')
async def revoke(request):
    return web.Response(text='Hello World!!!!')

@routes.post('/')
async def endpoint_handler(request):
    try:
        await handlers.handle_message(context, await request.read())
        return web.Response(text='Success')
    except Exception as e:
        traceback.print_exc()
        return web.Response(text=str(e))


async def main(loop):
    global port
    global server

    app = web.Application(loop=loop)
    app.add_routes(routes)
    app.router.add_static("/static/","static")
    aiohttp_session.setup(app, cookie_storage.EncryptedCookieStorage(b'Thirty  two  length  bytes  key.'))
    aiohttp_jinja2.setup(app,loader=jinja2.FileSystemLoader('static'))
    # noinspection PyDeprecation
    server = await loop.create_server(app.make_handler(), '0.0.0.0', port)

    print('Listening on port {}'.format(port))
    #await loop.create_task(example(loop))
    logging.info('Starting setup')
    await setup(loop)
    await asyncio.sleep(100*3600)

if __name__ == '__main__':
    mainloop = asyncio.get_event_loop()
    mainloop.run_until_complete(main(mainloop))
