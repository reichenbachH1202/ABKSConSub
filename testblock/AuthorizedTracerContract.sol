pragma solidity >=0.4.22 <0.6.0;
pragma experimental ABIEncoderV2;
import "./common.sol";

contract AuthorizedTracerContract is Common {
    TA private ta;
    mapping(address => bool) private TTList;

    constructor(TA memory _ta) public {
        ta = _ta;
    }

    modifier onlyTA() {
        require(tx.origin == ta.addr, "Only the TA is allowed");
        _;
    }

    function addTracer(address tracer) public onlyTA {
        TTList[tracer] = true;
    }

    function deleteTracer(address tracer) public onlyTA {
        TTList[tracer] = false;
    }

    function verifyTracer(address tracer) public view returns (bool) {
        return TTList[tracer];
    }
}
