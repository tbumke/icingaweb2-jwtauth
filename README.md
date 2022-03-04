# icingaweb2-jwtauth

This repository provides a modified version of the Icinga Web 2 `ExternalBackend` class and enables external authentication via JSON Web Token (JWT).

**Note**: Currently it only handles JWTs from [AWS ELB](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-authenticate-users.html).

## Requirements

- [PHP-JWT](https://github.com/firebase/php-jwt)
- [Sodium Compat](https://github.com/paragonie/sodium_compat) (optional)

## Installation

Install [composer](https://getcomposer.org/download/) and use it to download PHP requirements:

```shell
cd /usr/share/icingaweb2/library
composer require firebase/php-jwt
composer require paragonie/sodium_compat
```

Finally, clone this repository and replace default `ExternalBackend` class installed through the official Icinga Web 2 package:

```text
git clone https://github.com/yasysadm1n/icingaweb2-jwtauth.git
install -b -o root -g root -m 0644 icingaweb2-jwtauth/ExternalBackend.php /usr/share/php/Icinga/Authentication/User/ExternalBackend.php
```

## Final note on production readiness

First of all, I'm not a PHP developer and would like to hear your feedback on my modifications. Feel free to open issues and pull-requests if you would like to collaborate. The code is barely tested and at this point most likely NOT ready for production use.
