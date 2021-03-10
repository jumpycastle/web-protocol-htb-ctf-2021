#  [Sneaky](#Sneaky)
![category](https://img.shields.io/badge/category-forensics-orange)


### Description:
* Agent-50 delivered a network capture from a nearby enemy base. Can you find out the password that the enemy lieutenant used to sign in? Flag format: `HTB{password}`


### Objective:
* Locate the login attempt from a pcap and retrieve the password.


### Difficulty:
* `Easy` 


### Flag:
* `HTB{not_an_easy_password_to_guess}`


### Challenge:

For this challenge players are given a pcap file.

There is a login attempt to the private admin panel.

In order to locate the login procedure we must find the `POST` request.

![](https://i.imgur.com/VUB3yTL.png)

By following the stream:

![](https://i.imgur.com/kV32iIw.png)

The password is: `not_an_easy_password_to_guess`.
