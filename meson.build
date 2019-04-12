project('discord-linux-rpc', 'c')

add_project_arguments('-D_GNU_SOURCE', language : 'c')

libsystemd_dep = dependency('libsystemd')
yajl_dep = dependency('yajl')
prkit_dep = dependency('prkit', fallback : ['prkit', 'prkit_dep'])

prefix = get_option('prefix')
bindir = get_option('bindir')
libdir = get_option('libdir')

kill = find_program('kill')

conf_data = configuration_data()
conf_data.set('prefix', prefix)
conf_data.set('bindir', bindir)
conf_data.set('kill', kill.path())
configure_file(input : 'misc/discord-linux-rpc.service.in', output : 'discord-linux-rpc.service',
               configuration : conf_data,
               install_dir : join_paths(prefix, 'lib', 'systemd', 'user'))

executable('discord-linux-rpc', 'src/discord-linux-rpc.c',
           dependencies : [libsystemd_dep, yajl_dep, prkit_dep], install : true,
           install_rpath : join_paths(prefix, libdir))
meson.add_install_script('misc/setcap-net-admin.sh')
