import textwrap
from os import getenv


def version():
    """
    Extract static version part from VERSION file,
    git HEAD commit hash and message (if git module can be imported) and
    CircleCI build number.
    :return: (str, str, str, str)
    """
    static_version = open('VERSION').read().strip()
    try:
        import git
    except ImportError:
        commit = msg = None
    else:
        repo = git.Repo('.')
        head = repo.head.object
        commit = str(head)
        msg = head.message
    build_number = getenv('CIRCLE_BUILD_NUM', '0')
    return static_version, commit, msg, build_number


def version_string(static_version, commit_hash, build_number):
    """
    Format a full version string version.build_number~commit_hash.
    :param static_version: manually managed (static) version part, e.g. 0.1.5
    :param commit_hash: commit hash (optional)
    :param build_number: build number (doesn't have to be a number
    :return: str
    """
    return '{}.{}~{}'.format(static_version, build_number, commit_hash[:7]) if commit_hash \
           else '{}.{}'.format(static_version, build_number)


def write_changelog():
    import debian.changelog

    ver, commit, msg, build_number = version()
    ver_str = version_string(ver, commit, build_number)
    ch = debian.changelog.Changelog(open('debian/changelog'))
    ch.new_block(package='wott-agent',
                 version=ver_str,
                 distributions='stable',
                 urgency='medium',
                 author="%s <%s>" % debian.changelog.get_maintainer(),
                 date=debian.changelog.format_date())
    ch.add_change(textwrap.indent(msg, '  * '))
    ch.write_to_open_file(open('debian/changelog', 'w'))
