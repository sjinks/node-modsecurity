{
  "targets": [
    {
      "target_name": "modsecurity",
      "sources": [
        "src/main.cpp",
        "src/intervention.cpp",
        "src/engine.cpp",
        "src/rules.cpp",
        "src/transaction.cpp"
      ],
      'cflags!': [ '-fno-exceptions' ],
      'cflags_cc!': [ '-fno-exceptions', '-fno-rtti' ],
      'cflags_cc+': ['-frtti'],
      'conditions': [
        ["OS=='win'", {
          "defines": [
            "_HAS_EXCEPTIONS=1"
          ],
          "msvs_settings": {
            "VCCLCompilerTool": {
              "ExceptionHandling": 1
            },
          },
        }],
        ["OS=='mac'", {
          'xcode_settings': {
            'GCC_ENABLE_CPP_EXCEPTIONS': 'YES',
            'CLANG_CXX_LIBRARY': 'libc++',
            'MACOSX_DEPLOYMENT_TARGET': '10.7',
            'GCC_SYMBOLS_PRIVATE_EXTERN': 'YES'
          },
        }],
      ],
      "cflags+": [
        "-fvisibility=hidden"
      ],
      "include_dirs": [
        "<!(node -p \"require('node-addon-api').include_dir\")"
      ],
      "libraries": ['-L/usr/local/lib', '-lmodsecurity'],
      "defines": [
        "NODE_ADDON_API_DISABLE_DEPRECATED",
        # "NAPI_VERSION=<(napi_build_version)",
        "NODE_API_NO_EXTERNAL_BUFFERS_ALLOWED",
        "NAPI_VERSION=6",
        "NAPI_CPP_EXCEPTIONS"
      ]
    }
  ]
}
