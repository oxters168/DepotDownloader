DepotDownloader
===============

This is a fork of Depot Downloader. The intent of this fork is to allow this project to be capable of being plugged into an existing project that is already using the SteamKit2 library without hassle.


## Basic Usage

### Step 1

You need to give a location for the config file.
```
ConfigStore.LoadFromFile("DepotDownloader.config");
```
This needs to be the same each time since it holds the login keys of the users.

### Step2

Now you must create a Steam3Session object.
```
Steam3Session steam3 = new Steam3Session(steamClient, manager);
```
Provide it with your already created SteamClient and CallbackManager objects.

When you want to log the user in:
```
steam3.LoginAs(
          new SteamKit2.SteamUser.LogOnDetails()
          {
              Username = "username",
              Password = "password",
              ShouldRememberPassword = true/false,
          });
```



Alternatively if the user had already logged in before, you can directly put in the logon details in the constructor
```
string loginKey = null;
ConfigStore.TheConfig.LoginKeys.TryGetValue(username, out loginKey);

Steam3Session steam3 = new Steam3Session(
                steamClient,
                manager,
                new SteamUser.LogOnDetails()
                {
                    Username = username,
                    ShouldRememberPassword = true/false,
                    LoginKey = loginKey,
                });
```

### Step 3

Finally now you can use the ContentDownloader class functions
```
ContentDownloader.DownloadApp(steam3, "Papers Please", 239030);
```
The functions will always require the Steam3Session object we created before.

## Logging out

To log out just call:
```
steam3.Disconnect(true);
```

## Debugging
Just like in SteamKit2, you can implement the IDebugListener interface to receive debug messages and enable debug log:
```
DebugLog.AddListener(debugListener);
DebugLog.Enabled = true;
```
In the AddListener function, debugListener is the object that implements IDebugListener.
