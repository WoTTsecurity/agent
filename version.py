import textwrap
from os import getenv


def version():
    ver = open('VERSION').read().strip()
    try:
        import git
        repo = git.Repo('.')
        head = repo.head.object
        msg = head.message
        commit = str(head)
    except ModuleNotFoundError:
        commit = None
    build_number = getenv('CIRCLE_BUILD_NUM', '0')
    return ver, msg, commit, build_number


def version_string(ver, msg, commit, n):
    return '{}.{}~{}'.format(ver, n, commit[:7]) if commit \
           else '{}.{}'.format(ver, n)


def write_changelog():
    import debian.changelog

    ver, msg, commit, n = version()
    ver_str = version_string(ver, msg, commit, n)
    ch = debian.changelog.Changelog(open('debian/changelog'))
    ch.new_block(package='wott-agent',
                 version=ver_str,
                 distributions='stable',
                 urgency='medium',
                 author="%s <%s>" % debian.changelog.get_maintainer(),
                 date=debian.changelog.format_date())
    ch.add_change(textwrap.indent(msg, '  * '))
    ch.write_to_open_file(open('debian/changelog', 'w'))
