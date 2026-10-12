using System;
using System.IO;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Threading;

// A WPF window with a few controls. Once WPF has rendered it and it has been on screen for a few seconds it writes what it showed next
// to itself and closes, so a test can wait for it and keep a screenshot.
class Program
{
	[STAThread]
	static int Main()
	{
		var folder = Path.GetDirectoryName(typeof(Program).Assembly.Location);
		var application = new Application();
		var label = new TextBlock { Text = "WPF on .NET " + Environment.Version + (Environment.Is64BitProcess ? " 64-bit" : " 32-bit"),
			Margin = new Thickness(20, 20, 20, 8), FontSize = 16 };
		var box = new TextBox { Text = "Type here", Margin = new Thickness(20, 4, 20, 4), Width = 260, HorizontalAlignment = HorizontalAlignment.Left };
		var button = new Button { Content = "Click me", Margin = new Thickness(20, 4, 20, 4), Width = 100, HorizontalAlignment = HorizontalAlignment.Left };
		var check = new CheckBox { Content = "It works", IsChecked = true, Margin = new Thickness(20, 8, 20, 4) };
		var panel = new StackPanel();
		panel.Children.Add(label);
		panel.Children.Add(box);
		panel.Children.Add(button);
		panel.Children.Add(check);
		var window = new Window { Title = "Raven WPF", Width = 420, Height = 240, Content = panel, WindowStartupLocation = WindowStartupLocation.CenterScreen };
		var timer = new DispatcherTimer { Interval = TimeSpan.FromSeconds(4) };
		timer.Tick += (sender, args) =>
		{
			timer.Stop();
			File.WriteAllText(Path.Combine(folder, "wpf-out.txt"), window.Title + "|" + label.Text + "|" + box.Text + "|" + button.Content + "\r\n");
			window.Close();
		};
		// ContentRendered comes after the first frame has been drawn: only then has WPF's renderer worked.
		window.ContentRendered += (sender, args) => timer.Start();
		return application.Run(window);
	}
}
