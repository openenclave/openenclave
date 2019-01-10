cscript zip.vbs "oeenclave" "oeenclave.zip"
if exist "%USERPROFILE%\Documents\Visual Studio 2015\Templates\ProjectTemplates\Visual C++ Project" (
    copy "oeenclave.zip" "%USERPROFILE%\Documents\Visual Studio 2015\Templates\ProjectTemplates\Visual C++ Project"
)
if exist "%USERPROFILE%\Documents\Visual Studio 2017\Templates\ProjectTemplates\Visual C++ Project" (
    copy "oeenclave.zip" "%USERPROFILE%\Documents\Visual Studio 2017\Templates\ProjectTemplates\Visual C++ Project"
)

cscript zip.vbs "oeconsoleapp" "oeconsoleapp.zip"
if exist "%USERPROFILE%\Documents\Visual Studio 2015\Templates\ProjectTemplates\Visual C++ Project" (
    copy "oeconsoleapp.zip" "%USERPROFILE%\Documents\Visual Studio 2015\Templates\ProjectTemplates\Visual C++ Project"
)
if exist "%USERPROFILE%\Documents\Visual Studio 2017\Templates\ProjectTemplates\Visual C++ Project" (
    copy "oeconsoleapp.zip" "%USERPROFILE%\Documents\Visual Studio 2017\Templates\ProjectTemplates\Visual C++ Project"
)

cscript zip.vbs "oehostdll" "oehostdll.zip"
if exist "%USERPROFILE%\Documents\Visual Studio 2015\Templates\ProjectTemplates\Visual C++ Project" (
    copy "oehostdll.zip" "%USERPROFILE%\Documents\Visual Studio 2015\Templates\ProjectTemplates\Visual C++ Project"
)
if exist "%USERPROFILE%\Documents\Visual Studio 2017\Templates\ProjectTemplates\Visual C++ Project" (
    copy "oehostdll.zip" "%USERPROFILE%\Documents\Visual Studio 2017\Templates\ProjectTemplates\Visual C++ Project"
)
