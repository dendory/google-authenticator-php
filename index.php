<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN" "http://www.w3.org/TR/html4/loose.dtd">
<!--  Code (C) 2011 Patrick Lambert (dendory@gmail.com)  -  Provided under the MIT License  -->
<!--  Available from: http://dendory.net/twofactors  -->
<!--  PHP snippets in part based on the GA2PHP project: http://code.google.com/p/ga4php/  -->
<html>
	<head>
		<meta http-equiv="Content-Type" content="text/html;charset=utf-8" >
		<meta name="description" content="Google Authenticator Demo">
		<link href="../style.css" rel="stylesheet" type="text/css">
		<title>Google Authenticator Demo</title>
		<style>
			p
			{
				font-size: 12px;
			}
			input
			{
				color: #269;
				border: 1px solid #269;
				margin-top: 2px;
				margin-bottom: 2px;
			}
		</style>
	</head>
	<body>
			<div id="blog">
				<div id="news_txt">
					<h3><a href="../">Dendory.net</a> / twofactors</h3>
					<h2>Google Authenticator Demo</h2><br>

<?php
function oath_hotp ($key, $counter)
{
	$key = pack("H*", $key);
	$cur_counter = array(0,0,0,0,0,0,0,0);
	for($i=7;$i>=0;$i--)
	{
		$cur_counter[$i] = pack ('C*', $counter);
		$counter = $counter >> 8;
	}
	$bin_counter = implode($cur_counter);
	if(strlen($bin_counter) < 8)
	{
		$bin_counter = str_repeat (chr(0), 8 - strlen ($bin_counter)) . $bin_counter;
	}
	$hash = hash_hmac ('sha1', $bin_counter, $key);
	return $hash;
}

function oath_truncate($hash, $length = 6)
{
	foreach(str_split($hash,2) as $hex)
	{
		$hmac_result[]=hexdec($hex);
	}
	$offset = $hmac_result[19] & 0xf;
	return
	(
		(($hmac_result[$offset+0] & 0x7f) << 24 ) |
		(($hmac_result[$offset+1] & 0xff) << 16 ) |
		(($hmac_result[$offset+2] & 0xff) << 8 ) |
		($hmac_result[$offset+3] & 0xff)
	) % pow(10,$length);
}

function helperb322hex($b32)
{
	$alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	$out = "";
	$dous = "";
	for($i = 0; $i < strlen($b32); $i++)
	{
		$in = strrpos($alphabet, $b32[$i]);
		$b = str_pad(base_convert($in, 10, 2), 5, "0", STR_PAD_LEFT);
		$out .= $b;
		$dous .= $b.".";
	}
	$ar = str_split($out,20);
	$out2 = "";
	foreach($ar as $val)
	{
		$rv = str_pad(base_convert($val, 2, 16), 5, "0", STR_PAD_LEFT);
		$out2 .= $rv;
	}
	return $out2;
}

function sanitize($str)
{
	$str = sqlite_escape_string($str);
	$str = preg_replace("([^a-zA-Z0-9.@]*)", "", $str); 
	return substr($str, 0, 30);
}

if(isset($_POST['resetkey']) && isset($_POST['username'])) // reset
{
	$username = sanitize($_POST['username']);
	$resetkey = sanitize($_POST['resetkey']);
	if(strlen($username) < 2 || strlen($resetkey) < 2)
	{
		die("<b>Error:</b> Please enter a username and reset key.");
	}
	try
	{
		$db = new PDO("sqlite:gadb.sqlite");
		$count = $db->exec("DELETE FROM users WHERE username='" . sha1($username) . "' AND reset='" . $resetkey . "';");
		if($count > 0)  echo "<h4>Success!</h4><br><p>The username entry was removed from the list.</p>";
		else  echo "<b>Error:</b> Could not find the specified user.";
	} catch(PDOException $e) {
		die("<b>Error:</b> Something went wrong accessing the database.. Please try again later!");
	}
	$db = null;
}
else if(isset($_POST['username']) && isset($_POST['token'])) // login a user
{
	$token = sanitize($_POST['token']);
	$username = sanitize($_POST['username']);
	if(strlen($username) < 2 || strlen($token) < 2)
	{
		die("<b>Error:</b> Please enter a username and token.");
	}
	try 
	{
		$db = new PDO("sqlite:gadb.sqlite");
		$sql = "SELECT * FROM users WHERE username='" . sha1($username) . "';";
		foreach($db->query($sql) as $row)
		{
			if($row['username'] == sha1($username))
			{
				for($i=$row['count'];$i<($row['count']+10);$i++) // here we try 10 counts, in case the user pressed the button a few times
				{
					$a=oath_hotp(strtolower($row['key']), $i);
					if(oath_truncate($a) == $token)
					{
						$i++;
						$db->exec("UPDATE users SET count=" . $i . " WHERE username='" . sha1($username) . "';");
						die("<h4>Success!</h4><br><p>You've logged in successfully. You have logged in <b>" . $i . "</b> times so far.</p>");
					}
				}
			}
		}
	} catch(PDOException $e) {
		die("<b>Error:</b> Something went wrong accessing the database.. Please try again later!");
	}
	$db = null;
	echo "<h4>Failed!</h4><br><p>The login information is not valid. Please make sure you press the button on your Google Authenticator to generate a new token after each login attempt. Also, if you press it too many times between two logins, it will get out of sync and, for security, no longer function. You can reset your account from the previous page.</p>";
}
else if(isset($_POST['username'])) // register
{
	$username = sanitize($_POST['username']);
	if(strlen($username) < 2)
	{
		die("<b>Error:</b> Please enter a username.");
	}
	$alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
	$key = "";
	for($i=0; $i<16; $i++)
	{
		$offset = rand(0,strlen($alphabet)-1);
		$key .= $alphabet[$offset];
	}
	$hkey = helperb322hex($key);
	$resetkey = base_convert(mt_rand(0x1D39D3E06400000, 0x41C21CB8E0FFFFFF), 10, 36);
	try
	{
		$db = new PDO("sqlite:gadb.sqlite");
		$sql = "SELECT * FROM users WHERE username='" . sha1($username) . "';";
		foreach($db->query($sql) as $row)
		{
			if($row['username'] == sha1($username)) die("<b>Error:</b> The user name already exists.");
		}
		$db->exec("INSERT INTO users (ip, username, key, reset, count) VALUES ('" . $_SERVER['REMOTE_ADDR'] . "', '" . sha1($username) . "', '" . $hkey . "', '" . $resetkey . "', 0);");
	} catch(PDOException $e) {
		die("<b>Error:</b> Something went wrong accessing the database.. Please try again later!");
	}
	$db = null;
	echo "<h4>Success!</h4><br>";
	echo "<p><img src='googleauthenticator.jpg'></p>";
	echo "<br><p>The user name you entered has been added to the list. Download the Google Authenticator for your iPhone, Android phone or Blackberry, click the <b>+</b> sign and scan this with your phone camera:</p>";
	echo "<p><iframe scrolling=no frameborder=0 height=200px src='https://chart.googleapis.com/chart?cht=qr&chs=150x150&chl=otpauth://hotp/" . $username . "%3Fsecret%3D" . strtolower($key) . "%26counter%3D0'></iframe></p>";
	echo "<p>OR, if your phone has no camera, select <b>Counter-Based Mode</b> and the following key: <b>" .  $key . "</b></p>";
	echo "<p>Finally, note down this RESET KEY somewhere safe, so you can reset your account in case you lose your phone: <b>" . $resetkey . "</b></p>";
	echo "<br><p>That's it! Press the back button to login.</p>";
}
else // normal case
{
?>
			<p>This is a quick demo of how to implement <b>two-factor authentication</b> using the Google Authenticator on your own site or application. I created this page in less than 2 hours to show how trivial it is to do. Here, you can register a user name, and then login by using the information provided by the Google Authenticator. Note that this would also work with any OATH HOTP compliant hardware token.</p><br>
			<h4>Enroll</h4>
			<p>To try it out, simply enter a user name here. It can be anything, made of letters, numbers, dots or the at sign:</p>
			<p><form method="POST" action=".">
				User name: <input type="text" name="username"><br>
				<input type="submit" value="Enroll">
			</form></p><br>
			<h4>Login</h4>
			<p>Once you enrolled, enter your user name and the token from the Google Authenticator here:</p>
			<p><form method="POST" action=".">
				User name: <input type="text" name="username"><br>
				Current token: <input type="text" name="token"><br>
			<input type="submit" value="Login">
			</form></p><br>
			<h4>Reset account</h4>
			<p>If you ever lose your phone, use the <b>reset key</b> that was provided when you enrolled to reset your account:</p>
			<p><form method="POST" action=".">
				User name: <input type="text" name="username"><br>
				Reset key: <input type="text" name="resetkey"><br>
				<input type="submit" value="Reset">
			</form></p><br>
			<h4>Disclaimer</h4>
			<p>Please note that this site is a proof of concept and is not affiliated in any way with Google. The source code is publically available <a href="twofactors.tar">here</a>. Implementation of this system should be done over a secured site (SSL) to ensure security. The code is provided AS-IS and I am not responsible for what you do with it.</p>
<?php
}
?>
			</div>
			<div class="clear"></div>
			<div id="blogfooter">
				<p>&copy; 2011 <a href="mailto:dendory@gmail.com">Patrick Lambert</a><br><a href="http://creativecommons.org/licenses/by-nc-nd/3.0/"><img alt="Attribution-NonCommercial-NoDerivs 3.0" src="../license.png" border=0></a></p>
			</div>
		</div>
	</body>
</html>

