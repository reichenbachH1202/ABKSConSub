pragma solidity >=0.4.22 <0.6.0;
pragma experimental ABIEncoderV2;
import "./common.sol";
import "./AuthorizedTracerContract.sol";

contract FairTransactionContract is Common {
    mapping(address => TA) private TAMap;
    AuthorizedTracerContract private authContract;

    constructor(address _authContract) public {
        authContract = AuthorizedTracerContract(_authContract);
    }

    modifier onlyRegistered() {
        require(tx.origin == TAMap[tx.origin].addr, "Only the registered TAes are allowed");
        _;
    }

    function registTA() public {
        TA memory ta = TA(0, tx.origin);
        TAMap[tx.origin] = ta;
    }

    function reposit() public payable onlyRegistered returns (uint256) {
        TAMap[tx.origin].balance += msg.value;
    }

    function transferTo(address payable tracer, uint256 fee) public onlyRegistered returns(bool) {
        if (authContract.verifyTracer(tracer)) {
            TAMap[tx.origin].balance -= fee;
            tracer.transfer(fee);
            return true;
        }

        return false;
    }
}
