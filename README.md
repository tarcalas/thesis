# Thesis Project

This repo contains the code, the MAL languages, and some examples for my thesis
 
## MAL langs

The directory _mal-langs_ contains the three languages for the three levels (application, device, and network) on which I model systems.

## MAL models
The directory _mal-models_ contains some example models of systems/vulnerability chains

### Example 1

In this example a simple system is modelled. It consists of a network topology (as can be seen in `network-1.0.yml`), two devices (`dev1-1.0.yml` and `dev2-1.0.yml`), and three applications (`app1-1.0.yml`, `app2-1.0.yml`, and `app3-1.0.yml`).

The two devices are linked together through a datapipe (I used the asset name **`Port`** in all three languages, some other might be more passing, generally speaking we do not care about the exact mechanisms of communication and linking); this is described on the network level.

`Dev1` runs two applications (`app1` and `app2`), that communicate on the internal "channel"/`Port 420`. `app2` is accessible for unauthenticated users, but `app1` requires elevated privileges. If `app2`, if ran with eleveted privs, can send messages through `Port 80`. 

`Dev2` runs one application (`app3`), that, if ran with high privileges, can read the target data. It also accepts communication on `Port 80`.
 
All of this is described on the device level.

The applications are the modelled the most fine grained way; most importantly, this is the only level that shoud contain actual vulnerabilities. `app2` and `app3` contain PrivEsc vulnerabilities; exploiting these is quite straightforward, if one can access the applications `CoreModule`.