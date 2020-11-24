#!/bin/python3
import os
import sys
import argparse
import subprocess


def exists_image(args):
    return True if len(subprocess.check_output(['docker', 'images', f'pwnenv:{args.version}']).split(b'\n')) > 2 else False


def make_dockerfile(args):
    dockerfile = f'''\
            FROM ubuntu:{args.version}

            RUN ln -fs /usr/share/zoneinfo/Asia/Seoul /etc/localtime

            RUN apt update && apt install -y gdb git vim gcc-multilib g++-multilib python python3 python3-pip libcapstone3 ruby-full strace socat sudo
            RUN git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh
            RUN git clone https://github.com/JonathanSalwan/ROPgadget.git && cd ROPgadget && python3 setup.py install
            RUN gem install one_gadget
            '''

    with open('Dockerfile', 'wt') as f:
        f.write(dockerfile)


def build_image(args):
    r = True if os.system(f'docker build -t pwnenv:{args.version} .') == 0 else False
    os.remove('Dockerfile')
    return r


def build(args):
    if not exists_image(args):
            make_dockerfile(args)
            if not build_image(args):
                print('[!] Failed to build images.')
                sys.exit(0)
    else:
        print('[!] The image already exists')


def run_container(args):
    print('test')


def get_shell(args):
    pass


def clean(args):
    print('clean')
    pass


def main():
    parser = argparse.ArgumentParser(description='Pwnable environment based Docker.')
    pwnenv_help = lambda args: parser.print_help()
    parser.set_defaults(func=pwnenv_help)
    sub_parser = parser.add_subparsers(dest='subparser_name', help='sub-command')

    parser_build = sub_parser.add_parser('build', help='build pwnenv image')
    parser_run = sub_parser.add_parser('run', help='run conatiner')
    parser_stop = sub_parser.add_parser('stop', help='stop container')
    parser_clean = sub_parser.add_parser('clean', help='clean images or containers')

    parser_build.add_argument('version', type=float, choices=[16.04, 18.04, 20.04], nargs='?', default=20.04, help='environment image version(default: 20.04)')
    parser_build.set_defaults(func=build)

    parser_run.add_argument('version', type=float, choices=[16.04, 18.04, 20.04], nargs='?', default=20.04, help='environment image version(default: 20.04)')
    parser_run.add_argument('-b', '--binary', help='target binary with remote or local')
    run_remote = parser_run.add_argument_group('remote')
    remote_group = run_remote.add_mutually_exclusive_group()
    remote_group.add_argument('-r', '--remote', action='store_true', help='for remote environment')
    remote_group.add_argument('-d', '--debugging', action='store_true', help='for debugging core file from crashed remote')
    run_remote.add_argument('-p', '--port', type=int, default=1234, help='port fowarding for remote(default: 1234)')
    run_remote.add_argument('-u', '--user', default='ubuntu', help='users to run the target binary(default: ubuntu)')
    run_local = parser_run.add_argument_group('local')
    local_group = run_local.add_mutually_exclusive_group()
    local_group.add_argument('-l', '--local', action='store_true', help='for local environment(run a binary)')
    local_group.add_argument('-s', '--shell', action='store_true', help='for local environment(spawn a shell)')
    local_group.add_argument('-v', '--volume', help='mount a volume')
    parser_run.set_defaults(func=run_container)

    parser_clean.add_argument('-i', '--images', action='store_true', help='clean images')
    parser_clean.add_argument('-c', '--containers', action='store_true', help='clean container')
    parser_clean.set_defaults(func=clean)

    args = parser.parse_args()

    if args.subparser_name == 'run':
        if not args.remote or args.debugging or args.local or args.shell:
            parser_run.error('one of the arguments -r/--remote -d/--debugging -l/--local -s/--shell is required')

        if (args.remote or args.debugging) and (args.local or args.shell):
            parser_run.error('not allowed when used remote and local both')

        if (args.remote or args.local) and not args.binary:
            parser_run.error('the following arguments are required: -b/--binary')

    args.func(args)
    

if __name__ == '__main__':
    main()
