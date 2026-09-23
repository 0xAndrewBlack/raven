using System;
using System.Drawing;
using System.IO;
using System.Windows.Forms;

// A WinForms window with the common controls. Once it has been on screen for a few seconds it writes what it showed next to itself and
// closes, so a test can wait for it and keep a screenshot.
class Program
{
	[STAThread]
	static int Main()
	{
		var folder = Path.GetDirectoryName(typeof(Program).Assembly.Location);
		Application.EnableVisualStyles();
		var form = new Form { Text = "Raven .NET", ClientSize = new Size(420, 220), StartPosition = FormStartPosition.CenterScreen };
		var label = new Label { Text = "WinForms on .NET " + Environment.Version + (Environment.Is64BitProcess ? " 64-bit" : " 32-bit"),
			AutoSize = true, Location = new Point(20, 24) };
		var box = new TextBox { Location = new Point(20, 64), Width = 260, Text = "Type here" };
		var button = new Button { Text = "Click me", Location = new Point(290, 62), Width = 100 };
		var check = new CheckBox { Text = "It works", Location = new Point(20, 110), AutoSize = true, Checked = true };
		var list = new ComboBox { Location = new Point(20, 150), Width = 200, DropDownStyle = ComboBoxStyle.DropDownList };
		list.Items.AddRange(new object[] { "First", "Second", "Third" });
		list.SelectedIndex = 0;
		form.Controls.AddRange(new Control[] { label, box, button, check, list });
		var timer = new Timer { Interval = 4000 };
		timer.Tick += (sender, args) =>
		{
			timer.Stop();
			File.WriteAllText(Path.Combine(folder, "forms-out.txt"), form.Text + "|" + label.Text + "|" + box.Text + "|" + list.Text + "\r\n");
			form.Close();
		};
		form.Shown += (sender, args) => timer.Start();
		Application.Run(form);
		return 0;
	}
}
