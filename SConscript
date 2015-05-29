env = Environment(CCFLAGS = '-pipe -g -std=c++11', CXX='clang++')
src=Glob("*.cpp")

env.StaticLibrary('crypto_tools',src)
env.SharedLibrary('crypto_tools',src)
#env.Program('test',Glob('test/test.cpp'))
