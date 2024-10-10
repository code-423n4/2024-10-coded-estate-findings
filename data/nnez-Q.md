## Table of Contents
- [L-01 `setreservationforshortterm` doesn't check for `islisted` flag](#l-01-`setreservationforshortterm`-doesn't-check-for-`islisted`-flag)
- [L-02 Token owner might frontrun reservation transaction and change cancellation policy in short-term rental](#l-02-token-owner-might-frontrun-reservation-transaction-and-change-cancellation-policy-in-short-term-rental)
- [L-03 `rejectreservationforshortterm` is still callable on cancelled reservation could lead to token's owner losing their cancellation fee](#l-03-`rejectreservationforshortterm`-is-still-callable-on-cancelled-reservation-could-lead-to-token's-owner-losing-their-cancellation-fee)
- [L-04 Users can make reservation using time in the past](#l-04-users-can-make-reservation-using-time-in-the-past)
- [L-05 Cancelling bid should reject transaction with attached funds](#l-05-cancelling-bid-should-reject-transaction-with-attached-funds)
- [L-06 `setreservationforshortterm` should round up when calculating total days of renting](#l-06-`setreservationforshortterm`-should-round-up-when-calculating-total-days-of-renting)

## L-01 `setreservationforshortterm` doesn't check for `islisted` flag
### Proof-of-Concept
When a new token is minted, `ShortTermRental` initializes `islisted` flag to `None`.  
```rust
pub fn mint(
// function arguments
) -> Result<Response<C>, ContractError> {
    ...
    ... snipped
    ...

    let shortterm_rental = ShortTermRental {
        islisted: None,
        price_per_day: 0u64,
        available_period: vec![],
        deposit_amount: Uint128::from(0u64),
        withdrawn_amount: Uint128::from(0u64),
        denom: "ibc/F082B65C88E4B6D5EF1DB243CDA1D331D002759E938A0F5CD3FFDC5D53B3E349".to_string(),
        auto_approve: false,
        cancellation:vec![],
        minimum_stay:0u64,
    };
    ...
    ... snipped ...
    ...
}
```
Since `denom` is also initialized as USDC token and `setreservationforshortterm` doesn't check for `islisted` flag. There's a risk that malicious actors could make reservations with extremely long rental periods at no cost. This would prevent token owners from listing their properties for rent. However, token owners can always reject malicious reservations and proceed to list their properties.  

### Impact
Token owners may be unable to list their properties for rent due to malicious actors making reservations with extremely long rental periods at no cost. Token owners must then spend gas fees to reject these reservations. This issue could persist for a long time if malicious actors are dedicated to this strategy.  

### Recommended Mitigations
- Disallow the use of `setreservationforshortterm` function when `islisted` flag is disabled (false).  

## L-02 Token owner might frontrun reservation transaction and change cancellation policy in short-term rental    
### Proof-of-Concept  
For tokens with no previous reservations, token owners can potentially frontrun incoming reservations and change the cancellation policy to impose a high penalty. They can then approve the rental immediately after the reservation transaction is executed.  

The renter may be unable to cancel their reservations or receive the expected refund as indicated by the front-end when they initiate the cancellation transaction.  
```rust
pub fn cancelreservationafterapprovalforshortterm(
    &self,
    deps: DepsMut,
    info: MessageInfo,
    env: Env,
    token_id: String,
    renting_period: Vec<String>,
) -> Result<Response<C>, ContractError> {

    ...snipped...

    let diff_days = (check_in_time_timestamp - current_time)/86400;
    for (_i, item) in cancellation.iter().enumerate() {
        if item.deadline < diff_days {
            refundable_amount =  Uint128::new((amount.u128() * u128::from(item.percentage)) / 100); // @c4-contest: the penalty can be the total amount of deposited funds (0 percentage refund).
            break;
        }
    }
    ...snipped...
}
```
### Impact
Renter might not be able to get their refund.  
### Recommended Mitigtaion
Implement a delay before activating newly listed or re-listed tokens (after parameter changes).  

## L-03 `rejectreservationforshortterm` is still callable on cancelled reservation could lead to token's owner losing their cancellation fee
### Proof-of-Concept
When renters cancel approved reservations, the refundable amount is returned, and the cancellation fee is stored in `deposit_amount`. Token owners can claim this fee by calling `finalizeshorttermrental`.  

However, `rejectreservationforshortterm` can still be called by token owners on cancelled reservations. This function refunds the `deposit_amount` to the renter.  

If token owners mistakenly call `rejectreservationforshortterm` on a cancelled reservation, the cancellation fee will be refunded to the renter, resulting in a loss of cancellation fee for the token owner.  

```rust
pub fn cancelreservationafterapprovalforshortterm(
// function arguments
) -> Result<Response<C>, ContractError> {
    ...snipped...

    let diff_days = (check_in_time_timestamp - current_time)/86400;
    for (_i, item) in cancellation.iter().enumerate() {
        if item.deadline < diff_days {
            refundable_amount =  Uint128::new((amount.u128() * u128::from(item.percentage)) / 100);
            break;
        }
    }

    ...snipped...

    if position != -1 {
        // token.rentals.remove(position as usize);

        token.rentals[position as usize].cancelled = true; // <-- mark as cancelled
        // @c4-contest remaining deposit_amount is claimable by token owner when finalizing the rental
        token.rentals[position as usize].deposit_amount = amount - refundable_amount; 
        
    ... snipped ...
}

pub fn rejectreservationforshortterm(
// function arguments
) -> Result<Response<C>, ContractError> {
    
    ...snipped...

    let mut position: i32 = -1;
    let mut refundable_amount:Uint128 = Uint128::new(0);
    for (i, item) in token.rentals.iter().enumerate() {
        if item.address == Some(Addr::unchecked(traveler.clone()))
            // && item.renting_period == renting_period
            && item.renting_period[0].to_string() == renting_period[0]
            && item.renting_period[1].to_string() == renting_period[1]
        {
            position = i as i32;
            // @c4-contest: send deposit_amount back to renter
            if item.approved {
                // return Err(ContractError::ApprovedAlready {});
                refundable_amount = item.deposit_amount; 
            } else {
                refundable_amount = item.deposit_amount;
                
            }
        }
    }
    if position == -1 {
        return Err(ContractError::NotReserved {});
    } else {
        token.rentals.remove(position as usize);
        self.tokens.save(deps.storage, &token_id, &token)?;
    }

    Ok(Response::new()
        .add_attribute("action", "rejectreservationforshortterm")
        .add_attribute("sender", info.sender)
        .add_attribute("token_id", token_id)
        .add_message(BankMsg::Send {
            to_address: traveler,
            amount: vec![Coin {
                denom: token.shortterm_rental.denom,
                amount: refundable_amount,
            }],
        }))
}
```
### Impact
Token owners may mistakenly lose their entitled cancellation fees.  
### Recommended Mitigations  
- Disallow the use of `rejectreservationforshortterm` when `rental.cancelled` is `true`  

## L-04 Users can make reservation using time in the past  
### Proof-of-Concept
Both `setreservationforshortterm` and `setreservationforlongterm` lack validation of the check-in and check-out timestamps, allowing users to input past timestamps as the rentaing period.  
```rust
pub fn setreservationforshortterm(
// function arguments
) -> Result<Response<C>, ContractError> {
    let mut token = self.tokens.load(deps.storage, &token_id)?;
    let new_checkin = renting_period[0].parse::<u64>();
    let new_checkin_timestamp;

    match new_checkin {
        Ok(timestamp) => {
            new_checkin_timestamp = timestamp;
        }
        Err(_e) => {
            return Err(ContractError::NotReserved {});
        }
    }
    let new_checkout = renting_period[1].parse::<u64>();
    let new_checkout_timestamp;

    match new_checkout {
        Ok(timestamp) => {
            new_checkout_timestamp = timestamp;
        }
        Err(_e) => {
            return Err(ContractError::NotReserved {});
        }
    }

    if ((new_checkout_timestamp - new_checkin_timestamp)/ 86400) < token.shortterm_rental.minimum_stay {
        return Err(ContractError::LessThanMinimum {});
    }
    ...snipped...
}
pub fn setreservationforlongterm(
    // function arguments
) -> Result<Response<C>, ContractError> {
    let mut token = self.tokens.load(deps.storage, &token_id)?;
    let new_checkin = renting_period[0].parse::<u64>();
    let new_checkin_timestamp;

    match new_checkin {
        Ok(timestamp) => {
            new_checkin_timestamp = timestamp;
        }
        Err(_e) => {
            return Err(ContractError::NotReserved {});
        }
    }
    let new_checkout = renting_period[1].parse::<u64>();
    let new_checkout_timestamp;

    match new_checkout {
        Ok(timestamp) => {
            new_checkout_timestamp = timestamp;
        }
        Err(_e) => {
            return Err(ContractError::NotReserved {});
        }
    }

    ...snipped...
}
```
### Impact
Allowing reservations with past timestamps is illogical and could be exploited in conjunction with other time-sensitive vulnerabilities, as demonstrated in some high-severity issues.  
### Recommended Mitigations
- Check that `check_in` timestamp is not in the past (greater than current timestamp).  

## L-05 Cancelling bid should reject transaction with attached funds  
### Proof-of-Concept
Users can cancel their bids on tokens by calling `setbidtobuy` again. However, the current implementation lacks a check for attached funds during bid cancellation. If funds are attached, only the original bid amount is refunded, leading to the remaining funds being locked in the contract.

Although unlikely, there's a scenario where users might accidentally call `setbidtobuy` twice, attempting to buy a token. This could occur due to network conditions or user errors.
```rust
pub fn setbidtobuy(
// function arguments
) -> Result<Response<C>, ContractError> {
    ... snipped ...

    // @c4-contest: cancellation branch (position != -1 --> position exists)
    if position != -1 && (amount > Uint128::from(0u64)) {
        // @c4-contest: No check whether there are funds attached in this call
        Ok(Response::new()
        .add_attribute("action", "setbidtobuy")
        .add_attribute("sender", info.sender.clone())
        .add_attribute("token_id", token_id)
        .add_message(BankMsg::Send {
            to_address: info.sender.to_string(),
            amount: vec![Coin {
                denom: token.sell.denom,
                amount: amount, // @c4-contest: only the original bid amount is refunded
            }],
        }))
    }
    ... snipped ...

}
```
### Impact
Users' fund might get stuck
### Recommended Mitigations  
Check that `info.funds` is empty when users are cancelling the bid. If funds are attached, revert the transaction.  

## L-06 `setreservationforshortterm` should round up when calculating total days of renting  
The rental price for short-term stays is set per day. The rent_amount function calculates the total days by dividing the timestamp difference by 86400 seconds.  

However, due to integer division, the result is always rounded down. This creates a discrepancy between the rental days counted and the rental period recorded in seconds.  

Renters who reserve a property for 1 day and 23 hours only pay for one day due to rounding down. While token owners can reject these reservations, it's possible for them to go unnoticed, causing an unfair disadvantage to owner.  
```rust
pub fn setreservationforshortterm(
    &self,
    deps: DepsMut,
    info: MessageInfo,
    token_id: String,
    renting_period: Vec<String>,
    guests:usize,
) -> Result<Response<C>, ContractError> {
    ... snipped ...
    let rent_amount = token.shortterm_rental.price_per_day
    * (new_checkout_timestamp - new_checkin_timestamp)/(86400);
    ...
    ... snipped ...
    ...
    let traveler = Rental {
        denom:token.shortterm_rental.denom.clone(),
        rental_type:false,
        approved_date:None,
        deposit_amount: Uint128::from(rent_amount),
        renting_period: vec![new_checkin_timestamp, new_checkout_timestamp],
        address: Some(info.sender.clone()),
        approved: token.shortterm_rental.auto_approve,
        cancelled:false,
        guests:guests,
    };
    ... snipped ...
}
```
### Impact
Token owners may receive less payment than intended.  
### Recommended Mitigatoins  
- Rounding up when calculate the total days.   
OR  
- Change the price unit to price per second.  