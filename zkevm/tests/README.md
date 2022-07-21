# Integration test

## About trace examples:

Following shows The cost of each examples 

| Test case |    gas    | evm rows | state rows | storage rows | hash rows | Method* | Remarks |
| --------- | --------- | -------- | ---------- | ------------ | --------- | ------- | ------- |
| ERC20     | 32545 | 3733 | 1492 | 108 | 2774 | transfer | transfer to a recorded address (so cost less gas)
| ERC20 multiple | 241892 | 21691 | 8879 | 190 | 4940 | transfer * 5 | one tx fail for transfer to 0 address
| Nft | 122717 | 10376 | 4086 | 213 | 4826 | mint + transferFrom + burn |
| native | 21000 | 1 | 0 | 93 | 2280 | | "left unimplemented"
| greeter | 26706 | 909 | 282 | 138 | 2964 | set_value |
| chef | 107647 | 47094 | 19240 | 543 | 8018 | withdraw | withdraw from a profited pool with 1e18 deposition from the sushi-mock token
| DAO | 156710 | 46398 | 19466 | 262 | 5054 | propose + cancel |
| Empty | 1 | 0 | 0 | 0 | 0 | |

* Multiple methods are executed in the same block