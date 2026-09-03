using System;
using System.Diagnostics;
using System.IO;
using System.Xml;

static class Utils
{
	#region console utilities (shared style with AD.Test)

	internal static T Try<T>(string label, Func<T> value, ConsoleColor errColor = ConsoleColor.Red)
	{
		var s = Stopwatch.StartNew();
		try
		{
			Console.Write(label);
			var val = value();

			if (s.ElapsedMilliseconds > 50)
			{
				Console.ForegroundColor = ConsoleColor.DarkGray;
				Console.Write($"({s.ElapsedMilliseconds / 1000d:n2}s)\t");
				Console.ResetColor();
			}

			Console.WriteLine(val);
			return val;
		}
		catch (Exception ex)
		{
			Console.ForegroundColor = errColor;
			Console.WriteLine(ex.Message.TrimEnd());
			Console.ResetColor();
			return default;
		}
	}

	internal static void WriteLine(string msg, ConsoleColor color)
	{
		Console.ForegroundColor = color;
		Console.WriteLine(msg);
		Console.ResetColor();
	}

	// credits https://stackoverflow.com/a/3404522
	internal static string ReadPassword()
	{
		var pass = "";
		ConsoleKey key;
		do
		{
			var keyInfo = Console.ReadKey(intercept: true);
			key = keyInfo.Key;

			if (key == ConsoleKey.Backspace && pass.Length > 0)
			{
				Console.Write("\b \b");
				pass = pass.Remove(pass.Length - 1);
			}
			else if (!char.IsControl(keyInfo.KeyChar))
			{
				Console.Write("*");
				pass += keyInfo.KeyChar;
			}
		}
		while (key != ConsoleKey.Enter);
		Console.WriteLine();
		return pass;
	}

	#endregion

	#region SAML helpers

	/// <summary>
	/// Reads an appSettings value; if empty, prompts the user on the console.
	/// </summary>
	internal static string GetSetting(string key, string prompt, bool required = true)
	{
		var value = System.Configuration.ConfigurationManager.AppSettings[key];
		if (string.IsNullOrWhiteSpace(value))
		{
			Console.WriteLine(prompt + (required ? "" : " (optional, leave empty to skip)") + ":");
			value = Console.ReadLine();
		}
		if (required && string.IsNullOrWhiteSpace(value))
			throw new Exception($"Missing required setting '{key}'.");
		return value?.Trim();
	}

	/// <summary>Opens the default system browser at the given url.</summary>
	internal static void OpenBrowser(string url)
	{
		// UseShellExecute lets Windows pick the default browser.
		Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
	}

	/// <summary>Reads a request/stream fully as UTF-8 text.</summary>
	internal static string ReadToEnd(this Stream stream)
	{
		using (var reader = new StreamReader(stream, System.Text.Encoding.UTF8))
			return reader.ReadToEnd();
	}

	/// <summary>Pretty-prints a raw XML string with indentation (best effort).</summary>
	internal static string PrettyXml(string xml)
	{
		try
		{
			var doc = new XmlDocument { XmlResolver = null };
			doc.LoadXml(xml);
			var sb = new System.Text.StringBuilder();
			var settings = new XmlWriterSettings { Indent = true, IndentChars = "  ", OmitXmlDeclaration = true };
			using (var xw = XmlWriter.Create(sb, settings))
				doc.WriteTo(xw);
			return sb.ToString();
		}
		catch { return xml; }
	}

	#endregion
}
