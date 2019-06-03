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
    return ver, msg, commit


def write_changelog():
    import debian.changelog

    ver, msg, commit = version()
    ch = debian.changelog.Changelog(open('debian/changelog'))
    ch.new_block(package='wott-agent',
                 version=ver + commit,
                 distributions='stable',
                 urgency='medium',
                 author="%s <%s>" % debian.changelog.get_maintainer(),
                 date=debian.changelog.format_date())
    ch.add_change(textwrap.indent(msg, '  * '))
    ch.write_to_open_file(open('debian/changelog', 'w'))
