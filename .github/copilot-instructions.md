# Copilot instructions for the Fashion project
# Copilot instructions — Fashion (single-page storefront)

This is a tiny static SPA. The entire UI, styles and JavaScript live in `index.html`.

Core facts
- Single file: open `fashion/index.html` to run and edit; there is no build or package manager.
- In-memory state: `products`, `cart` are arrays defined in `index.html`. Data is not persisted by default.
- Admin gating: `currentUser.isAdmin` controls visibility of `.admin-only` elements; the admin UI is in `#adminSection`.

Conventions you'll rely on
- Global functions drive behaviour: e.g. `renderProducts()`, `filterProducts(category)`, `addToCart(id)`, `openCart()`, `proceedToCheckout()`, `placeOrder()`.
- DOM-by-id pattern: key IDs include `productsGrid`, `cartCount`, `productForm`, `imageInput`, `cartModal`, `checkoutModal`.
- Styling is inlined in `<head>`; reuse existing classes (`.product-card`, `.modal`, `.admin-panel`, `.admin-only`).
- Images are often data URIs. Admin uploads use a `FileReader` and set `currentImage`.

Developer workflows (practical)
- Run locally: open `index.html` in a browser, or from the project root run a lightweight server: `python -m http.server 8000` and visit `http://localhost:8000/`.
- Debugging: use the browser console — most issues are runtime JS errors (uncaught exceptions break UI). Refresh after edits.

Project-specific pitfalls and actionable fixes
- placeOrder runtime bug: `placeOrder()` contains malformed HTML assignment (raw angle-bracket text used without a string or template literal). Fix by using a template string, for example:

  document.getElementById('confirmationDetails').innerHTML = `
    <div class="order-summary">
      <h4>Order Details</h4>
      ${cart.map(item => `<p>${item.name} - ${item.price} ETB</p>`).join('')}
      <p><strong>Total: ${total} ETB</strong></p>
      <p>Delivery to: ${orderData.shipping.address}, ${orderData.shipping.city}</p>
      <p>Payment: ${orderData.payment}</p>
    </div>
  `;

  (This is the minimal, discoverable fix — search for the broken `placeOrder` block in `index.html` and replace it with the snippet above.)

- Event usage: handlers sometimes assume a global `event`. Prefer explicit parameters: `function filterProducts(category, e) { e = e || window.event; ... }` or bind handlers via `addEventListener` to avoid fragile implicit globals.

- Persistence option (small improvement): to persist state use `localStorage` keys like `fashion_products` and `fashion_cart` — load them on startup and call a small `saveState()` after changes.

Where to look for examples
- Product list / render: `renderProducts()` in `index.html` (uses `productsGrid` and maps `products` → card HTML).
- Admin add: `#productForm` submit handler shows how new products are constructed and pushed to `products`.
- Checkout flows: `proceedToCheckout`, `goToPayment`, `goToReview`, `placeOrder` implement the steps and DOM updates.

Editing contract (small, safe changes)
- Keep changes scoped to `index.html` unless introducing server code; keep the app runnable by opening `index.html`.
- Test changes by reloading in the browser and verifying console has no uncaught errors.

If you plan larger changes
- If adding a backend or build tools, add a `README.md` and `package.json` and keep PRs small. Document any new scripts in `README.md`.

Questions or missing details?
- Tell me which area you'd like more examples for (e.g., a ready localStorage adapter, a fixed `placeOrder` patch applied automatically, or a suggested tiny test harness) and I'll iterate.
