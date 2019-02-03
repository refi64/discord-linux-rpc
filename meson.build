project('discord-linux-rpc', 'c')

add_project_arguments('-D_GNU_SOURCE', language : 'c')

libdiscordrpc_proj = subproject('discord-rpc')
libdiscordrpc_dep = libdiscordrpc_proj.get_variable('libdiscordrpc_dep')

libsystemd_dep = dependency('systemd')

prefix = get_option('prefix')
bindir = get_option('bindir')

conf_data = configuration_data()
conf_data.set('prefix', prefix)
conf_data.set('bindir', bindir)
configure_file(input : 'misc/discord-linux-rpc.service.in', output : 'discord-linux-rpc.service',
               configuration : conf_data,
               install_dir : join_paths(prefix, 'lib', 'systemd', 'user'))

executable('discord-linux-rpc', 'src/discord-linux-rpc.c',
           dependencies : [libdiscordrpc_dep, libsystemd_dep], install : true)
meson.add_install_script('misc/setcap-net-admin.sh')
