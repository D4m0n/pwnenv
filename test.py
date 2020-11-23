import argparse

parser = argparse.ArgumentParser()

sub_parser = parser.add_subparsers(help='sub command')

parser_run = sub_parser.add_parser('run')
parser_build = sub_parser.add_parser('build')

parser_run.add_argument('-v', '--version')

parser_build.add_argument('-i', '--images')


parser.parse_args()
