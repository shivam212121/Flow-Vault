"""
# /home/ubuntu/flowvault_backend_fastapi/routers/stripe_router.py

import os
import stripe
from fastapi import APIRouter, HTTPException, Request, Header, Depends
from pydantic import BaseModel
import logging

# Placeholder for database connection/session and authentication dependency
# from ..dependencies import get_db_session, get_current_active_user
# from ..core.config import settings # For Stripe API keys and webhook secret

logger = logging.getLogger(__name__)
router = APIRouter(
    prefix="/api/v1/stripe",
    tags=["stripe"],
    # dependencies=[Depends(get_current_active_user)], # Add auth dependency later
)

# Configure Stripe API key (ideally from environment variables or config)
# stripe.api_key = settings.STRIPE_SECRET_KEY
stripe.api_key = os.environ.get("STRIPE_SECRET_KEY", "sk_test_YOUR_STRIPE_SECRET_KEY") # Replace with your test secret key
STRIPE_WEBHOOK_SECRET = os.environ.get("STRIPE_WEBHOOK_SECRET", "whsec_YOUR_STRIPE_WEBHOOK_SECRET") # Replace with your webhook secret

class CreateCheckoutSessionRequest(BaseModel):
    price_id: str # e.g., price_xxxxxxxxxxxxxx for a specific plan
    # quantity: int = 1 # If quantity is variable

class CheckoutSessionResponse(BaseModel):
    session_id: str
    url: str

@router.post("/create-checkout-session", response_model=CheckoutSessionResponse)
async def create_checkout_session(request_data: CreateCheckoutSessionRequest):
    # user = Depends(get_current_active_user)
    # customer_id = user.stripe_customer_id # Assuming you store Stripe customer ID
    # if not customer_id:
        # Create a new Stripe customer or fetch existing
        # customer = stripe.Customer.create(email=user.email, name=user.name)
        # customer_id = customer.id
        # Update user record with customer_id
    
    # For now, using a mock customer or allowing Stripe to create one
    try:
        checkout_session = stripe.checkout.Session.create(
            # customer=customer_id, # Associate with existing customer if available
            payment_method_types=["card"],
            line_items=[
                {
                    "price": request_data.price_id,
                    "quantity": 1,
                },
            ],
            mode="subscription", # or "payment" for one-time
            success_url="http://localhost:3000/dashboard/billing?session_id={CHECKOUT_SESSION_ID}&status=success", # Replace with your frontend success URL
            cancel_url="http://localhost:3000/dashboard/billing?status=cancelled",       # Replace with your frontend cancel URL
            # automatic_tax={"enabled": True}, # If using Stripe Tax
            # metadata={"user_id": user.id} # Store your internal user ID
        )
        logger.info(f"Created Stripe Checkout Session: {checkout_session.id}")
        return {"session_id": checkout_session.id, "url": checkout_session.url}
    except Exception as e:
        logger.error(f"Stripe Checkout Session creation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/webhook")
async def stripe_webhook(request: Request, stripe_signature: Optional[str] = Header(None)):
    payload = await request.body()
    try:
        event = stripe.Webhook.construct_event(
            payload, stripe_signature, STRIPE_WEBHOOK_SECRET
        )
    except ValueError as e:
        # Invalid payload
        logger.error(f"Stripe Webhook ValueError: {e}")
        raise HTTPException(status_code=400, detail="Invalid payload")
    except stripe.error.SignatureVerificationError as e:
        # Invalid signature
        logger.error(f"Stripe Webhook SignatureVerificationError: {e}")
        raise HTTPException(status_code=400, detail="Invalid signature")

    # Handle the event
    logger.info(f"Received Stripe event: {event.type}")
    if event.type == "checkout.session.completed":
        session = event.data.object
        # Fulfill the purchase (e.g., grant access, update subscription status in DB)
        # user_id = session.metadata.get("user_id")
        # stripe_customer_id = session.customer
        # stripe_subscription_id = session.subscription
        logger.info(f"Checkout session completed for session ID: {session.id}")
        # Example: update_user_subscription(user_id, stripe_customer_id, stripe_subscription_id, "active")
    elif event.type == "invoice.payment_succeeded":
        invoice = event.data.object
        # Handle successful payment (e.g., for recurring subscriptions)
        logger.info(f"Invoice payment succeeded for invoice ID: {invoice.id}")
    elif event.type == "invoice.payment_failed":
        invoice = event.data.object
        # Handle failed payment (e.g., notify user, update subscription status)
        logger.info(f"Invoice payment failed for invoice ID: {invoice.id}")
    elif event.type == "customer.subscription.updated" or event.type == "customer.subscription.deleted" or event.type == "customer.subscription.created":
        subscription = event.data.object
        # Handle subscription changes (e.g., plan change, cancellation, new subscription)
        # status = subscription.status (e.g., "active", "canceled", "past_due")
        logger.info(f"Subscription {subscription.id} status updated to {subscription.status}")
        # Example: update_user_subscription_status(subscription.id, subscription.status)
    else:
        logger.warning(f"Unhandled Stripe event type: {event.type}")

    return {"status": "success"}

@router.post("/create-customer-portal-session")
async def create_customer_portal_session():
    # user = Depends(get_current_active_user)
    # stripe_customer_id = user.stripe_customer_id
    # if not stripe_customer_id:
    #     raise HTTPException(status_code=404, detail="Stripe customer ID not found for this user.")
    
    # Mock customer ID for now
    stripe_customer_id = "cus_mockcustomerid"

    try:
        portal_session = stripe.billing_portal.Session.create(
            customer=stripe_customer_id,
            return_url="http://localhost:3000/dashboard/billing", # URL to return to after portal interaction
        )
        logger.info(f"Created Stripe Customer Portal Session for customer: {stripe_customer_id}")
        return {"url": portal_session.url}
    except Exception as e:
        logger.error(f"Stripe Customer Portal Session creation failed: {e}")
        raise HTTPException(status_code=500, detail=str(e))

# Add more endpoints as needed, e.g., to list products/prices, get subscription details for a user.

"""
