# Changelog

## 1.1.1 / 2023-12-23

## What's Changed
* bugfix for no data to retrieve crashes validator
* change vpermit tao limit to 500
* don't ping validators
* don't monitor every step, too often
* don't ping all miners every monitor
* reduce challenge per step, too much load
* don't whitelist by default
* record forward time, punish 1/2 on ping unavail
* switch over to separate encryption wallet without sensitive data
* Fix broken imports and some typos
* up ping timeout limit, caused issues with incorrectly flagging UIDs as down
* bugfix in verify store with miners no longer returning data, verify on validator side with seed
* incresae challenge timeout
* update version key
