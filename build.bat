@echo off
call "C:\Program Files\Microsoft Visual Studio\18\Community\VC\Auxiliary\Build\vcvarsall.bat" x64
cmake -G "Visual Studio 18 2026" -A x64 -DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl -DCMAKE_BUILD_TYPE=Release -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreaded -DCMAKE_INTERPROCEDURAL_OPTIMIZATION=ON -DRE_WERROR=ON -B build
cmake --build build --config Release