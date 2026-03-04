project(lifted-cli)

add_executable(lifted-cli
    "main.cpp"
)

# eval-suite pulls in lifted (and all its transitive PUBLIC deps — LLVM, LIEF,
# remill, unicorn) so there is no need to list them again here.
target_link_libraries(lifted-cli PRIVATE eval-suite)
