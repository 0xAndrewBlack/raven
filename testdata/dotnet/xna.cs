using System;
using System.IO;
using System.Reflection;
using Microsoft.Win32;

// What a game looks for before it starts on the XNA Framework 4.0: the framework's key in the 32-bit registry view and its assemblies in
// the global assembly cache. The main assembly is read without running it, since XNA is 32-bit only. The findings go next to the program.
class Program
{
	static int Main()
	{
		var folder = Path.GetDirectoryName(typeof(Program).Assembly.Location);
		var report = "";
		using (var machine = RegistryKey.OpenBaseKey(RegistryHive.LocalMachine, RegistryView.Registry32))
		using (var key = machine.OpenSubKey(@"SOFTWARE\Microsoft\XNA\Framework\v4.0"))
		{
			report += "key " + (key == null ? "missing" : "Installed=" + key.GetValue("Installed") + " NativeLibraryPath=" + key.GetValue("NativeLibraryPath"));
		}
		var windows = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
		var assembly = Path.Combine(windows, @"Microsoft.NET\assembly\GAC_32\Microsoft.Xna.Framework\v4.0_4.0.0.0__842cf8be1de50553\Microsoft.Xna.Framework.dll");
		report += "|assembly " + (File.Exists(assembly) ? AssemblyName.GetAssemblyName(assembly).FullName : "missing");
		File.WriteAllText(Path.Combine(folder, "xna-out.txt"), report + "\r\n");
		return report.Contains("Installed=1") && report.Contains("Microsoft.Xna.Framework, Version=4.0.0.0") ? 0 : 1;
	}
}
