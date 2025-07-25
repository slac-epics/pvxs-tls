set(CMAKE_SYSTEM_NAME Windows)
set(CMAKE_SYSTEM_PROCESSOR AMD64)
set(CMAKE_C_COMPILER x86_64-w64-mingw32-gcc)
set(CMAKE_CXX_COMPILER x86_64-w64-mingw32-g++)
set(CMAKE_RC_COMPILER x86_64-w64-mingw32-windres)
set(CMAKE_FIND_ROOT_PATH  /usr/x86_64-w64-mingw32 )
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)

# Explicitly set OpenSSL paths for cross-compilation
set(OPENSSL_ROOT_DIR /usr/x86_64-w64-mingw32)
set(OPENSSL_INCLUDE_DIR /usr/x86_64-w64-mingw32/include)
set(OPENSSL_LIBRARIES /usr/x86_64-w64-mingw32/lib64)
set(OPENSSL_USE_STATIC_LIBS TRUE)
