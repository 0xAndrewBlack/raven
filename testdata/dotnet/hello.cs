using System;
using System.IO;

// A console program for the .NET Framework: it says which runtime and width ran it, in a file next to it, and returns 42.
class Hello
{
	static int Main()
	{
		var folder = Path.GetDirectoryName(typeof(Hello).Assembly.Location);
		File.WriteAllText(Path.Combine(folder, "hello-out.txt"), "Hello from .NET " + Environment.Version + " " + (IntPtr.Size * 8) + "-bit\r\n");
		return 42;
	}
}
