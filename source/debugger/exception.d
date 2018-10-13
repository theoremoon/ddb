module debugger.exception;

import std.exception;

static class DebuggerException : Exception
{
    mixin basicExceptionCtors;
}
