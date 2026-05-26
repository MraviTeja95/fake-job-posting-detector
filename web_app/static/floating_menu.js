/* =========================================================
   FLOATING MENU INTERACTION — SafeRecruit AI
   Handles expand/collapse toggle and close on item click
========================================================= */

document.addEventListener('DOMContentLoaded', function() {
    const floatingMenu = document.getElementById('floatingMenu');
    const floatingTrigger = document.getElementById('floatingTrigger');
    const floatingItems = document.querySelectorAll('.floating-item');
    
    if (!floatingMenu || !floatingTrigger) return;
    
    // Toggle menu on trigger click
    floatingTrigger.addEventListener('click', function(e) {
        e.stopPropagation();
        floatingMenu.classList.toggle('active');
    });
    
    // Close menu on item click
    floatingItems.forEach(item => {
        item.addEventListener('click', function(e) {
            // Don't prevent navigation, just close menu before redirect
            floatingMenu.classList.remove('active');
        });
    });
    
    // Close menu on outside click
    document.addEventListener('click', function(e) {
        if (!floatingMenu.contains(e.target)) {
            floatingMenu.classList.remove('active');
        }
    });
    
    // Close menu on Escape key
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape' && floatingMenu.classList.contains('active')) {
            floatingMenu.classList.remove('active');
        }
    });
});
