UPDATE observations SET evidence='probe-response' WHERE evidence='probed' AND service IN ('tcpwrapped','unknown','');
