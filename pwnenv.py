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


def run_container(args):
    pass


def stop_container(args):
    pass


def get_shell(args):
    pass


def clean(args):
    pass


def main():
    parser = argparse.ArgumentParser(description='Pwnable environment based Docker.')
    sub_parser = parser.add_subparsers(help='sub-command')

    parser_build = sub_parser.add_parser('build', help='build pwnenv image')
    parser_run = sub_parser.add_parser('run', help='run conatiner')
    parser_stop = sub_parser.add_parser('stop', help='stop container')
    parser_clean = sub_parser.add_parser('clean', help='clean images or containers')

    parser_build.add_argument('version', type=float, choices=[16.04, 18.04, 20.04], default=20.04, help='environment image version(default: 20.04)')
    parser_build.set_defaults(func=build_image)

    #parser_run.add_argument('version', type=float, choices=[16.04, 18.04, 20.04], default=20.04, help='environment image version(default: 20.04)')
    parser_run.add_argument('-u', '--user', default='ubuntu', help='users to run the target binary(default: ubuntu)')
    parser_run.add_argument('-r', '--remote', action='store_true', help='for remote environment')
    parser_run.add_argument('-d', '--debugging', action='store_true', help='for local debugging environment')
    parser_run.add_argument('-p', '--port', type=int, help='port fowarding for remote')

    parser_clean.add_argument('-i', '--images', action='store_true', help='clean images')
    parser_clean.add_argument('-c', '--containers', action='store_true', help='clean container')
    args = parser.parse_args()
    print()
    
    '''
    if 'build' in args.command and 'run' in args.command:
        if not exists_image(args):
            make_dockerfile(args)
            if not build_image(args):
                print('[!] Failed to build images.')
                sys.exit(0)
        if 'run' in args.command:
            run_container(args)
    elif 'stop' in args.command:
        stop_container(args)
    elif 'shell' in args.command:
        get_shell(args)
    elif 'clean' in args.command:
        if args.images or args.containers:
            clean(args)
        else:
            '[!] Choose what you want to clean'
            sys.exit(0)
    else:
        pass
    '''

if __name__ == '__main__':
    main()
