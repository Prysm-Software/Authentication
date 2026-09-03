using System;
using System.Diagnostics;


static class Utils
{

	#region utilities

	/// <summary>
	/// Writes <paramref name="label"/>, runs <paramref name="value"/> and prints its result on the
	/// same line. If the call throws, the exception message is printed in <paramref name="errColor"/>
	/// and <c>default(T)</c> is returned so the diagnostic keeps going. Calls taking more than 50 ms
	/// are annotated with their duration, to help spot slow domain/network round-trips.
	/// </summary>
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
				Console.Write($"({s.ElapsedMilliseconds/1000d:n2}s)	");
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


	/// <summary>
	/// Reads a password from the console, echoing '*' for each character and honouring Backspace.
	/// credits https://stackoverflow.com/a/3404522
	/// </summary>
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
}
