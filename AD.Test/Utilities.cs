using System;


static class Utils
{

	#region utilities
	internal static T Try<T>(string label, Func<T> value, ConsoleColor errColor = ConsoleColor.Red)
	{
		try
		{
			Console.Write(label);
			var val = value();
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
}
