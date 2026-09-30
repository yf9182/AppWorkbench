"""One JSON envelope for every command, including parser and transport errors."""
import argparse
import json
import os
from pathlib import Path
import sys
from .errors import WorkbenchError
from .security import safe_json, read_json, scan_sensitive
from .engine import Engine

class Parser(argparse.ArgumentParser):
    def error(self, message):
        raise WorkbenchError('arguments', 'Invalid command arguments; use --help for the supported interface')
    def print_help(self, file=None):
        value = {'ok': True, 'command': 'help', 'result': {'usage': self.format_help()}}
        print(json.dumps(value, ensure_ascii=False), file=file or sys.stdout)

def parser():
    p = Parser(prog='wb', description='Conversation-led, human-confirmed product iterations')
    p.add_argument('--home', default=os.environ.get('APP_WORKBENCH_HOME', str(Path.home()/'.config/app-workbench')))
    sub = p.add_subparsers(dest='command', required=True)
    sub.add_parser('init').add_argument('--sources')
    product = sub.add_parser('product').add_subparsers(dest='operation', required=True)
    product.add_parser('list')
    for command in ['show', 'inspect']:
        product.add_parser(command).add_argument('product')
    product.add_parser('register').add_argument('--file', required=True)
    collect = sub.add_parser('collect'); collect.add_argument('product'); collect.add_argument('--sources', nargs='+', choices=['ga4','apple','cloudflare','legacy']); collect.add_argument('--days', type=int, default=28)
    iteration = sub.add_parser('iteration').add_subparsers(dest='operation', required=True)
    create = iteration.add_parser('create'); create.add_argument('product'); create.add_argument('--plan', required=True); create.add_argument('--targets', nargs='+')
    revise = iteration.add_parser('revise'); revise.add_argument('id'); revise.add_argument('--plan', required=True); revise.add_argument('--targets', nargs='+')
    approve = iteration.add_parser('approve'); approve.add_argument('id'); approve.add_argument('--actor', required=True); approve.add_argument('--message', required=True)
    for command in ['status','pause','resume']:
        iteration.add_parser(command).add_argument('id')
    ls = iteration.add_parser('list'); ls.add_argument('--product')
    for command, operation in [('candidate','set'),('review','record')]:
        s = sub.add_parser(command).add_subparsers(dest='operation', required=True).add_parser(operation)
        s.add_argument('id'); s.add_argument('--file', required=True)
    check = sub.add_parser('check'); check.add_argument('id'); check.add_argument('--target', required=True); check.add_argument('--name')
    deliver = sub.add_parser('deliver'); deliver.add_argument('id'); deliver.add_argument('--target', required=True); deliver.add_argument('--action', required=True); deliver.add_argument('--parameters', help='JSON file containing nonsecret action parameters')
    rec = sub.add_parser('reconcile'); rec.add_argument('id'); rec.add_argument('--action-id', required=True)
    accept = sub.add_parser('accept'); accept.add_argument('id'); accept.add_argument('--file', required=True)
    evidence = sub.add_parser('evidence').add_subparsers(dest='operation', required=True).add_parser('add')
    evidence.add_argument('id'); evidence.add_argument('--file', required=True); evidence.add_argument('--source', required=True); evidence.add_argument('--binding', help='JSON file with commit/version/source binding')
    export = sub.add_parser('export'); export.add_argument('--output', required=True)
    backup = sub.add_parser('backup'); backup.add_argument('--output', required=True); backup.add_argument('--key-file', required=True)
    restore = sub.add_parser('restore'); restore.add_argument('--input', required=True); restore.add_argument('--key-file', required=True); restore.add_argument('--destination', required=True)
    serve = sub.add_parser('serve'); serve.add_argument('--host', default='127.0.0.1'); serve.add_argument('--port', type=int, default=8765)
    return p

def dispatch(args):
    # Restoration must not create the destination (or the default state) before validation.
    if args.command == 'restore':
        from .migration import restore
        return restore(args.input, args.key_file, args.destination)
    root = Path(args.home).expanduser()
    if root.is_symlink():
        raise WorkbenchError('unsafe_path', 'Workbench home cannot be a symlink')
    engine = Engine(root)
    try:
        cmd, op = args.command, getattr(args, 'operation', None)
        if cmd == 'init': return engine.registry.initialize(args.sources)
        if cmd == 'product':
            if op == 'list':
                return [{'id':p['id'],'name':p['name'],'repositories':len(p['repositories']),'category':p.get('workflow',{}).get('category'),'goal':p.get('workflow',{}).get('goal')} for p in engine.registry.all()]
            if op == 'register': return engine.registry.register(read_json(args.file))
            product = engine.registry.get(args.product)
            if op == 'show': return product
            engine.registry.validate(product)
            return {'product':product['id'],'capabilities':engine.adapter.inspect_product(product,engine.root)}
        if cmd == 'collect': return engine.collect(args.product,args.sources,args.days)
        if cmd == 'iteration':
            if op == 'create': return engine.create(args.product,args.plan,args.targets)
            if op == 'revise': return engine.revise(args.id,args.plan,args.targets)
            if op == 'approve': return engine.approve(args.id,args.actor,args.message)
            if op == 'list': return engine.store.all(args.product)
            if op == 'status': return engine.status(args.id)
            return engine.control(args.id,op)
        if cmd == 'candidate': return engine.candidate(args.id,read_json(args.file))
        if cmd == 'review': return engine.review(args.id,read_json(args.file))
        if cmd == 'check': return engine.check(args.id,args.target,args.name)
        if cmd == 'deliver': return engine.deliver(args.id,args.target,args.action,read_json(args.parameters) if args.parameters else {})
        if cmd == 'reconcile': return engine.reconcile(args.id,args.action_id)
        if cmd == 'accept': return engine.accept(args.id,read_json(args.file))
        if cmd == 'evidence': return engine.evidence(args.id,args.file,args.source,read_json(args.binding) if args.binding else None)
        if cmd == 'export':
            from .dashboard import export
            return export(engine.root,args.output)
        if cmd == 'backup':
            from .migration import backup
            return backup(engine.root,args.output,args.key_file)
        if cmd == 'serve':
            from .dashboard import serve
            return serve(engine.root,args.host,args.port)
    finally:
        engine.store.close()

def main(argv=None):
    command = 'arguments'
    try:
        args = parser().parse_args(argv)
        command = args.command + ((' ' + args.operation) if getattr(args,'operation',None) else '')
        result = safe_json(dispatch(args))
        ok = not isinstance(result,dict) or result.get('status') not in {'failed','uncertain','unverified'}
        print(json.dumps({'ok':ok,'command':command,'result':result},ensure_ascii=False))
        return 0 if ok else 1
    except WorkbenchError as error:
        print(json.dumps({'ok':False,'command':command,'error':{'code':error.code,'message':safe_json(str(error))}},ensure_ascii=False))
        return 2
    except KeyboardInterrupt:
        print(json.dumps({'ok':False,'command':command,'error':{'code':'interrupted','message':'Interrupted; inspect saved state and reconcile pending external actions before retry'}}))
        return 130
    except Exception as error:
        # Neither exception text nor traceback may expose provider secrets.
        print(json.dumps({'ok':False,'command':command,'error':{'code':'internal_error','message':'Operation could not be verified ('+type(error).__name__+')'}}))
        return 2
