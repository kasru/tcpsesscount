cmake_minimum_required(VERSION 3.10)

project(tcpsesscount)

add_executable(${PROJECT_NAME}
  list.h
  list.c
  error.h
  tcppacket.h
  tcppacket.c
  tcpstat.h
  tcpstat.c
  main.c
)

option(TRACE "build with trace" OFF)
if( TRACE )
     add_definitions(-DTRACE)
endif()

if( NOT CMAKE_BUILD_TYPE )
   set( CMAKE_BUILD_TYPE Release ... FORCE )
endif()

if(CMAKE_BUILD_TYPE MATCHES Debug)
     add_definitions(-DDEBUG)
else()
     add_definitions(-DNDEBUG)
endif()

target_compile_options(${PROJECT_NAME} PRIVATE -Werror -Wall -Wextra -Wconversion)

target_link_libraries(${PROJECT_NAME} pcap)
