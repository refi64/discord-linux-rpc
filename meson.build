project('discord-linux-rpc', 'c')

add_project_arguments('-D_GNU_SOURCE', language : 'c')

libdiscordrpc_proj = subproject('discord-rpc')  # XXX
libdiscordrpc_dep = libdiscordrpc_proj.get_variable('libdiscordrpc_dep')

executable('discord-linux-rpc', 'src/discord-linux-rpc.c', dependencies : libdiscordrpc_dep,
           install : true)
