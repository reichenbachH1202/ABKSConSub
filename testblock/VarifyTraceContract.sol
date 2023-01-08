pragma solidity >=0.4.22 <0.6.0;
pragma experimental ABIEncoderV2;
import "./common.sol";
import "./AuthorizedTracerContract.sol";
import "./FairTransactionContract.sol";

contract TraitorTracerContract {
    struct Tag {
        uint256[] GID;
        uint256[] epsilon;
    }

    FairTransactionContract private transactionContract;

    constructor (address _transactionContract) public {
        transactionContract = FairTransactionContract(_transactionContract);
    }

    function pairing(uint256 a, uint256 b) public pure returns(uint256) {
        return a * b;
    }

    function keySanityCheck(uint256[] memory GID, uint256[] memory epsilon, address payable tracer, uint256 sdk_sub, uint256 H) public {
        uint256 g = 0;
        uint256 fee = 100;
        for (uint256 i = 0; i < GID.length; i++) {
            uint256 y = epsilon[i] * pairing(g, sdk_sub * H);
            if (y == pairing(g, sdk_sub)) {
                transactionContract.transferTo(tracer, fee);
                continue;
            }

            return;
        }
    }
}
