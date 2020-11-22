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
            RUN useradd -m {args.user}
            WORKDIR /home/{args.user}

            RUN apt update && apt install -y gdb git vim gcc-multilib g++-multilib python python3 python3-pip libcapstone3 ruby-full strace socat
            USER {args.user}
            RUN git clone https://github.com/pwndbg/pwndbg && cd pwndbg && ./setup.sh
            RUN git clone https://github.com/JonathanSalwan/ROPgadget.git && cd ROPgadget && python setup.py install
            RUN gem install one_gadget
            '''

    with open('Dockerfile', 'wt') as f:
        f.write(dockerfile)


def build_image(args):
    r = True if os.system(f'docker build -t pwnenv:{args.version} .') == 0 else False
    os.remove('Dockerfile')
    return r


def run(args):
    pass


def stop():
    pass


def main():
    parser = argparse.ArgumentParser(description='Pwnable environment based Docker.')
    parser.add_argument('path', type=str, help='target files you pwning here(docker volume)')
    parser.add_argument('-v', '--version',type=float, choices=[16.04, 18.04, 20.04], default=20.04, help='environment image version(default: 20.04)')
    parser.add_argument('-u', '--user', default='ubuntu', help='users to run the target binary(default: ubuntu)')
    args = parser.parse_args()
    
    if not exists_image(args):
        make_dockerfile(args)
        if not build_image(args):
            print('[!] Failed to build images.')
            sys.exit(0)

if __name__ == '__main__':
    main()
