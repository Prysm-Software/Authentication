using System;
using System.Configuration;
using System.Diagnostics;
using System.Text.Encodings.Web;
using System.Text.Json;

static class Utils
{
	#region console utilities (shared style with AD.Test and SAML.Test)

	internal static T Try<T>(string label, Func<T> value, ConsoleColor errColor = ConsoleColor.Red) => Try(label, value, out _, errColor);

	/// <summary>Runs a step and prints its result and duration; a failure prints its message, returned in <paramref name="error"/>.</summary>
	internal static T Try<T>(string label, Func<T> value, out string error, ConsoleColor errColor = ConsoleColor.Red)
	{
		var s = Stopwatch.StartNew();
		error = null;
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
			error = Describe(ex);
			Console.ForegroundColor = errColor;
			Console.WriteLine(error);
			Console.ResetColor();
			return default;
		}
	}

	/// <summary>Message of an exception followed by the distinct messages of its inner exceptions (the real cause of an HTTP failure).</summary>
	internal static string Describe(Exception ex)
	{
		var message = ex.Message.TrimEnd();
		for (var inner = ex.InnerException; inner != null; inner = inner.InnerException)
			if (!message.Contains(inner.Message.TrimEnd()))
				message += $" ({inner.Message.TrimEnd()})";
		return message;
	}

	internal static void WriteLine(string msg, ConsoleColor color)
	{
		Console.ForegroundColor = color;
		Console.WriteLine(msg);
		Console.ResetColor();
	}

	/// <summary>Something to fix, with what to do about it.</summary>
	internal static void Warn(string msg) => WriteLine("    ! " + msg, ConsoleColor.Yellow);

	#endregion

	#region settings and JSON helpers

	/// <summary>Reads an appSettings value, null when empty.</summary>
	internal static string Setting(string key) => ConfigurationManager.AppSettings[key] is { } value && !string.IsNullOrWhiteSpace(value) ? value.Trim() : null;

	/// <summary>Reads an appSettings value; if empty, prompts the user on the console.</summary>
	internal static string GetSetting(string key, string prompt, bool required = true)
	{
		var value = Setting(key);
		if (value == null)
		{
			Console.WriteLine(prompt + (required ? "" : " (optional, leave empty to skip)") + ":");
			value = Console.ReadLine();
		}
		if (required && string.IsNullOrWhiteSpace(value))
			throw new Exception($"Missing required setting '{key}'.");
		return value?.Trim();
	}

	static readonly JsonSerializerOptions Indented = new() { WriteIndented = true, Encoder = JavaScriptEncoder.UnsafeRelaxedJsonEscaping };

	/// <summary>Pretty-prints a JSON text with indentation (best effort).</summary>
	internal static string PrettyJson(string json)
	{
		try
		{
			using var doc = JsonDocument.Parse(json);
			return JsonSerializer.Serialize(doc.RootElement, Indented);
		}
		catch { return json; }
	}

	/// <summary>String value of a property, null when missing; a non-string value gives its JSON text.</summary>
	internal static string Str(this JsonElement element, string name) =>
		element.ValueKind == JsonValueKind.Object && element.TryGetProperty(name, out var value) ? value.ValueKind == JsonValueKind.String ? value.GetString() : value.ToString() : null;

	/// <summary>Unix time (seconds) as a local date and time.</summary>
	internal static string Local(long unixSeconds) => DateTimeOffset.FromUnixTimeSeconds(unixSeconds).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss");

	#endregion
}
