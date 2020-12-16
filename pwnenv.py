#!/usr/bin/python3
import os
import re
import sys
import argparse
import subprocess


def check_docker():
    try:
        return subprocess.check_output(['which', 'docker']).decode().strip('\n')
    except:
        print('[!] Docker is not installed.')
        exit()

DOCKER = check_docker()
GDB = '/usr/bin/gdb'
WORKDIR = os.curdir


def exists_image(args):
    return True if len(subprocess.check_output([DOCKER, 'images', f'pwnenv:{args.version}']).split(b'\n')) > 2 else False


def build(args):
    def make_dockerfile(args):
        dockerfile = f'''\
                FROM ubuntu:{args.version}
                RUN ln -fs /usr/share/zoneinfo/Asia/Seoul /etc/localtime
                RUN apt update && apt install -y gdb git vim gcc-multilib g++-multilib python python3 python3-pip libcapstone3 ruby-full strace socat sudo
                RUN git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh
                RUN git clone https://github.com/JonathanSalwan/ROPgadget.git && cd ROPgadget && python3 setup.py install
                RUN gem install one_gadget
                '''

        with open(os.curdir + '/Dockerfile', 'wt') as f:
            f.write(dockerfile)


    def build_image(args):
        r = True if subprocess.call([DOCKER, 'build', '-t', f'pwnenv:{args.version}', WORKDIR]) == 0 else False
        os.remove(os.curdir + '/Dockerfile')
        return r


    if not exists_image(args):
            make_dockerfile(args)
            if not build_image(args):
                print('[!] Failed to build images.')
                sys.exit(0)
    else:
        print('[!] The image already exists')


def run_container(args):
    if not exists_image(args):
        build(args)

    args_volume = ['-v', args.volume and f'{args.volume["src"]}:{args.volume["target"]}']
    if args.remote:
        args_docker = [DOCKER, 'run', '--rm', '--name', f'pwnenv-{args.version}-remote', '-p', f'{args.port}:{args.port}', '-it', '--ulimit', 'core=-1','-v', f'{args.binary}:/binary', f'pwnenv:{args.version}', 'socat', f'TCP-LISTEN:{args.port},reuseaddr,fork', 'EXEC:"strace -f /binary"']
        args.volume and args_docker.insert(10, ''.join(args_volume))
        subprocess.call(args_docker)
    elif args.crashed:
        container_id = subprocess.check_output([DOCKER, 'ps', '-a', '-q', '-f', f'name=pwnenv-{args.version}-remote']).decode().strip('\n')
        subprocess.call([DOCKER, 'exec', '-it', container_id, 'sh', '-c', f'{GDB} -c core'])
    elif args.local:
        args_docker = [DOCKER, 'run', '--rm', '-it', '-v', f'{args.binary}:/binary', f'pwnenv:{args.version}', '/binary']
        args.volume and args_docker.insert(3, ''.join(args_volume))
        subprocess.call(args_docker)
    elif args.debugging:
        args_docker = [DOCKER, 'run', '--rm', '-it', '-v', f'{args.binary}:/binary', f'pwnenv:{args.version}', 'sh', '-c', f'{GDB} /binary']
        args.volume and args_docker.insert(3, ''.join(args_volume))
        subprocess.call(args_docker)
    elif args.shell:
        container_id = subprocess.check_output([DOCKER, 'ps', '-a', '-q', '-f', f'name=pwnenv-{args.version}-shell']).decode().strip('\n')
        if not container_id:
            args_docker = [DOCKER, 'run', '--name', f'pwnenv-{args.version}-shell', '-it', '--ulimit', 'core=-1', f'pwnenv:{args.version}', '/bin/bash']
            args.volume and args_docker.insert(7, ''.join(args_volume))
            subprocess.call(args_docker)
        else:
            if subprocess.check_output([DOCKER, 'ps', '-q', '-f', f'id={container_id}', '-f', 'status=exited']).decode().strip('\n'):
                subprocess.call([DOCKER, 'start', container_id])
            subprocess.call([DOCKER, 'attach', container_id])


def clean(args):
    if args.containers:
        containers = subprocess.check_output([DOCKER, 'ps', '-a', '-f', 'name=pwnenv']).decode().split('\n')
        if not containers[1:-1]:
            print('[!] Containers not exists.')
            exit()
        print('    '+containers[0])
        containers = containers[1:-1]
        for i, container in enumerate(containers):
            print(f'[{i}] {container}')
        idx_list = ['']
        while idx_list == ['']:
            idx_list = input('choose the index of the containers you want to clean[a or idx,]: ').split(',')
        if len(idx_list) == 1 and idx_list[0] == 'a':
            [subprocess.call([DOCKER, 'stop', f'{containers[i].split()[0]}']) for i in range(len(containers))]
            [subprocess.call([DOCKER, 'rm', f'{containers[i].split()[0]}']) for i in range(len(containers))]
        else:
            idx_list = map(int, idx_list)
            for idx in idx_list:
                if idx < 0 or idx >= len(containers):
                    print('[!] index out of range')
                    exit()
                subprocess.call([DOCKER, 'stop', f'{containers[idx].split()[0]}'])
                subprocess.call([DOCKER, 'rm', f'{containers[idx].split()[0]}'])

    if args.images:
        images = subprocess.check_output([DOCKER, 'images', 'pwnenv']).decode().split('\n')
        if not images[1:-1]:
            print('[!] Images not exists.')
            exit()
        print('    '+images[0])
        images = images[1:-1]
        for i, image in enumerate(images):
            print(f'[{i}] {image}')
        idx_list = input('choose the index of the images you want to clean[a or idx,]: ').split(',')
        if len(idx_list) == 1 and idx_list[0] == 'a':
            [subprocess.call([DOCKER, 'rmi', f'pwnenv:{images[i].split()[1]}']) for i in range(len(images))]
        else:
            idx_list = map(int, idx_list)
            for idx in idx_list:
                if idx < 0 or idx >= len(images):
                    print('[!] index out of range')
                    exit()
                subprocess.call([DOCKER, 'rmi', f'pwnenv:{images[idx].split()[1]}'])


def main():
    parser = argparse.ArgumentParser(description='Pwnable environment based Docker.')
    parser.add_argument('--version', action='version', version='%(prog)s 0.1')
    pwnenv_help = lambda args: parser.print_help()
    parser.set_defaults(func=pwnenv_help)
    sub_parser = parser.add_subparsers(dest='subparser_name', help='sub-command')

    parser_build = sub_parser.add_parser('build', help='build pwnenv image')
    parser_run = sub_parser.add_parser('run', help='run conatiner')
    parser_clean = sub_parser.add_parser('clean', help='clean images or containers')

    def type_version(string):
        if re.match(r'^(1[6-9]|20)\.(04|10)$', string):
            return string
        else:
            raise argparse.ArgumentTypeError('version is invalid')

    parser_build.add_argument('version', type=type_version, nargs='?', default='20.04', help='environment image version(default: 20.04)')
    parser_build.set_defaults(func=build)

    def type_binary(string):
        path = os.path.abspath(string)
        if os.path.exists(path):
            return path
        else:
            raise argparse.ArgumentTypeError('path is not exists.')
    def type_volume(string):
        string = string.split(':')
        if len(string) == 2:
            src, target = string
            src = os.path.abspath(src)
            if os.path.exists(src):
                return {'src':src, 'target':target}
            else:
                raise argparse.ArgumentTypeError(f'path is not exists')
        else:
            raise argparse.ArgumentTypeError(f'required format src:target')
    parser_run.add_argument('version', type=type_version, nargs='?', default='20.04', help='environment image version(default: 20.04)')
    parser_run.add_argument('-b', '--binary', type=type_binary, help='target binary with remote or local')
    parser_run.add_argument('-v', '--volume', default=False, type=type_volume, help='mount a volume')
    run_remote = parser_run.add_argument_group('remote')
    remote_group = run_remote.add_mutually_exclusive_group()
    remote_group.add_argument('-r', '--remote', action='store_true', help='for remote environment')
    remote_group.add_argument('-c', '--crashed', action='store_true', help='for debugging core file from crashed remote')
    run_remote.add_argument('-p', '--port', type=int, default=1234, help='port fowarding for remote(default: 1234)')
    # run_remote.add_argument('-u', '--user', default='ubuntu', help='users to run the target binary(default: ubuntu)')
    run_local = parser_run.add_argument_group('local')
    local_group = run_local.add_mutually_exclusive_group()
    local_group.add_argument('-l', '--local', action='store_true', help='for local environment(run a binary)')
    local_group.add_argument('-d', '--debugging', action='store_true', help='for debugging with gdb')
    local_group.add_argument('-s', '--shell', action='store_true', help='for local environment(spawn a shell)')
    parser_run.set_defaults(func=run_container)

    parser_clean.add_argument('-i', '--images', action='store_true', help='clean images')
    parser_clean.add_argument('-c', '--containers', action='store_true', help='clean container')
    parser_clean.set_defaults(func=clean)

    args = parser.parse_args()

    if args.subparser_name == 'run':
        if not any([args.remote, args.crashed, args.local, args.debugging, args.shell]):
            parser_run.error('one of the arguments -r/--remote -c/--crashed -l/--local -d/--debugging -s/--shell is required')

        if (args.remote or args.crashed) and (args.local or args.shell):
            parser_run.error('not allowed when used remote and local both')

        if (args.remote or args.local or args.debugging) and not args.binary:
            parser_run.error('the following arguments are required: -b/--binary')

    if args.subparser_name == 'clean':
        if not any([args.images, args.containers]):
            parser_clean.error('one of the arguments -i/--images -c/--containers is required')

    args.func(args)
    

if __name__ == '__main__':
    main()
