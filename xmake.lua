set_plat("windows")
set_arch("x86")

-- Add the release and debug rules
-- (release will be used by default unless you pass -m)
add_rules("mode.release", "mode.debug")

-- Optional: force the windows platform and 32-bit arch when configuring via
-- `xmake f` you can alsopass these on the command line:
-- `xmake f -p windows -a x86 -m release`
target("security_access")
    -- Set the target kind to a shared library (.dll)
    set_kind("shared")
    -- Set the C and C++ language standards
    set_languages("c11", "c++17")
    -- Recursively add all C source files from lib and src directories
    add_files("src/**.c")
    -- Recursively add all header files from lib and src directories
    add_headerfiles("src/**.h")

    -- Initialize the include directories list with base folders
    local includes = {".", "src", "test"}
    -- Dynamically find and add all subdirectories in src to the includes list
    for _, dir in ipairs(os.dirs("src/**")) do table.insert(includes, dir) end

    -- Apply the collected include directories to the target
    add_includedirs(includes)
    -- Set the C runtime library to multi-threaded (MT)
    set_runtimes("MT")

    -- Define a test suite for the security access module
    add_tests("security_access_test", {
        -- The test target is a standalone binary
        kind = "binary",
        -- Use C11 for the test code
        languages = "c11",
        -- The main test source file
        files = {"test/test.c"},
        -- Reuse the same include directories as the main target
        includes = includes
    })

    -- Optimization and linker flags for release mode
    if is_mode("release") then
        -- Enable Level 2 optimizations (/O2)
        add_cxflags("/O2", { force = true })
        -- Disable incremental linking for faster final builds
        add_ldflags("/INCREMENTAL:NO", { force = true })
    end

target("test")
    set_kind("phony")
