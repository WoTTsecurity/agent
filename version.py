import git
import textwrap


def version():
    ver = open('VERSION').read().strip()
    repo = git.Repo('.')
    assert not repo.bare
    heads = repo.heads
    master = heads.master
    msg = master.commit.message
    commit = str(master.commit)
    ncommits = len(list(repo.iter_commits()))
    return ver, msg, commit, ncommits


def version_string(ver, msg, commit, n):
    return '{}-{}~{}'.format(ver, commit[:7], n), msg


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
