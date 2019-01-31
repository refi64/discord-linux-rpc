project('discord-rpc', ['c', 'cpp'])

inc = include_directories('include')

add_project_arguments(
  '-Wno-unknown-pragmas',
  '-Wno-old-style-cast',
  '-Wno-c++98-compat',
  '-Wno-c++98-compat-pedantic',
  '-Wno-missing-noreturn',
  '-Wno-padded',
  '-Wno-covered-switch-default',
  '-Wno-exit-time-destructors',
  '-Wno-global-constructors',
  language : ['c', 'cpp'])

thread_dep = dependency('threads')

libdiscordrpc = static_library('libdiscordrpc', ['src/discord_rpc.cpp', 'src/rpc_connection.cpp',
                                                 'src/serialization.cpp',
                                                 'src/discord_register_linux.cpp',
                                                 'src/connection_unix.cpp'],
                               include_directories : inc)

libdiscordrpc_dep = declare_dependency(include_directories : inc, link_with : libdiscordrpc,
                                       dependencies : thread_dep)
