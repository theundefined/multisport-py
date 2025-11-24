import asyncio
import logging
import os

from dotenv import load_dotenv

from multisport_py import MultisportClient

# --- Configuration ---
# Load environment variables from .env file
load_dotenv()

# Set up basic logging
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Get credentials from environment
USERNAME = os.getenv("MULTISPORT_USERNAME")
PASSWORD = os.getenv("MULTISPORT_PASSWORD")


async def main():
    """Demonstrate the MultisportClient usage."""
    if not USERNAME or not PASSWORD or "example.com" in USERNAME:
        logging.error("Please provide your MultiSport credentials in the .env file.")
        return

    logging.info(f"Attempting to log in as {USERNAME}...")
    client = MultisportClient(username=USERNAME, password=PASSWORD)

    try:
        await client.login()

        if client.access_token:
            logging.info("Login successful!")
            logging.info(f"Access Token (first 20 chars): {client.access_token[:20]}...")

            # --- Test fetching user info ---
            logging.info("Fetching user info...")
            user_info = await client.get_user_info()
            logging.info(f"User Info: {user_info}")

            # --- Test fetching authorized users (to get product ID) ---
            logging.info("Fetching authorized users...")
            auth_users = await client.get_authorized_users()
            logging.info(f"Authorized Users: {auth_users}")

            # --- Test fetching limits and history ---
            if auth_users and auth_users.get("products"):
                product_id = auth_users["products"][0].get("id")
                if product_id:
                    logging.info(f"Found product ID: {product_id}")

                    logging.info("Fetching card limits...")
                    limits = await client.get_card_limits(product_id)
                    logging.info(f"Card Limits: {limits}")

                    logging.info("Fetching card history for the last 30 days...")
                    from datetime import date, timedelta

                    date_to = date.today()
                    date_from = date_to - timedelta(days=30)

                    history = await client.get_card_history(
                        product_id,
                        date_from=date_from.isoformat(),
                        date_to=date_to.isoformat(),
                    )
                    logging.info(f"Card History: {history}")

                    # --- Test fetching relations ---
                    logging.info("Fetching relations...")
                    relations = await client.get_relations()
                    logging.info(f"Relations: {relations}")

                else:
                    logging.warning("Could not find product ID in authorized users response.")
            else:
                logging.warning("No products found in authorized users response.")

        else:
            logging.error("Login failed, no access token was retrieved.")

    except Exception as e:
        logging.error(f"An error occurred during the test: {e}", exc_info=True)
    finally:
        await client.close()
        logging.info("Client session closed.")


if __name__ == "__main__":
    asyncio.run(main())
