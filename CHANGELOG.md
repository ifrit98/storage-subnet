# Changelog

## 1.2.0 / 2023-12-29

## What's Changed
* hotfix challenge adjustment and reduce rewards vector size by @ifrit98 in https://github.com/ifrit98/storage-subnet/pull/47
* Validator fix block hash selection by @Rubberbandits in https://github.com/ifrit98/storage-subnet/pull/48
* Exploring storage/miner/run and setting weights logic. Enhacing logic to control more scenarios by @eduardogr in https://github.com/ifrit98/storage-subnet/pull/51
* Package by @ifrit98 in https://github.com/ifrit98/storage-subnet/pull/49
* Improve miner stats visibility in logging by @ifrit98 in https://github.com/ifrit98/storage-subnet/pull/44
* add migration script and database func to move filepaths of data index by @ifrit98 in https://github.com/ifrit98/storage-subnet/pull/50

## New Contributors
* @Rubberbandits made their first contribution in https://github.com/ifrit98/storage-subnet/pull/20

**Full Changelog**: https://github.com/ifrit98/storage-subnet/commits/v1.2.0


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
