'use strict';
'require baseclass';
'require ui';

return baseclass.extend({
	menuIcons: {
		'fwx_network': 'fwx_network',
		'fwx_wireless': 'fwx_wireless',
		'fwx_parental_control': 'fwx_parental_control',
		'fwx_advance': 'fwx_advance',
		'fwx_dashboard': 'fwx_dashboard',
		'fwx_internet_record': 'fwx_internet_record',
		'fwx_user': 'fwx_user',
		'fwx_monitor': 'fwx_monitor',
	},
	defaultIcon: 'default',
	__init__() {
		ui.menu.load().then(L.bind(this.render, this));
		window.addEventListener('resize', L.bind(this.handleResize, this));
	},
	
	isMobileDevice() {
		const userAgent = navigator.userAgent || navigator.vendor || window.opera;
		const mobileRegex = /android|webos|iphone|ipad|ipod|blackberry|iemobile|opera mini/i;
		const isMobileUA = mobileRegex.test(userAgent);
		
		const width = window.innerWidth || document.documentElement.clientWidth || document.body.clientWidth;
		const isMobileWidth = width <= 768;
		
		const isTouchDevice = 'ontouchstart' in window || navigator.maxTouchPoints > 0;
		
		const isHighDPR = window.devicePixelRatio && window.devicePixelRatio > 1;

		const isMobile = isMobileUA && isMobileWidth;
		
		const isMobileLandscape = isMobileUA && width > 768 && width <= 1024;
		
		const result = isMobile || isMobileLandscape;
		

		return result;
	},
	
	isWideScreen() {
		return !this.isMobileDevice();
	},
	
	handleResize() {
		clearTimeout(this.resizeTimer);
		this.resizeTimer = setTimeout(() => {
			const isWide = this.isWideScreen();
			const sidebarNav = document.querySelector('.sidebar-nav');
			
			if (isWide) {
				if (sidebarNav) {
					sidebarNav.style.display = '';
				}
			} else {
				if (sidebarNav) {
					sidebarNav.style.display = 'none';
				}
			}
		}, 200);
	},

	getMenuIcon(menuName) {
		return this.menuIcons[menuName] || this.defaultIcon;
	},

	generateMenuIconClass(menuName) {
		const iconName = this.getMenuIcon(menuName);
		return `menu-icon-${iconName}`;
	},

	render(tree) {
		let node = tree;
		let url = '';
		this.renderModeMenu(tree);
		this.renderCategoryNav(); 
		this.renderBreadcrumb(tree);

		let currentLevel = 0;
		if (L.env.dispatchpath.length >= 3) {
			for (var i = 0; i < 3 && node; i++) {
				node = node.children[L.env.dispatchpath[i]];
				url = url + (url ? '/' : '') + L.env.dispatchpath[i];
			}

			currentLevel = 1;

			if (node)
				this.renderTabMenu(node, url, currentLevel);
		}

		const isWide = this.isWideScreen();
		const menuSelector = isWide ? '#topmenu' : '#topmenu-mobile';
		const menuContainer = document.querySelector(menuSelector);
		const hasRenderedMenu = !!(menuContainer && menuContainer.children.length > 0);
		if (!hasRenderedMenu) {
			if (isWide) {
				this.renderMainMenu(node, url, currentLevel);
			} else {
				this.renderMobileMenu(node, url, currentLevel);
			}
		}
		
		setTimeout(() => {
			this.handleResize();
		}, 100);
	},

	renderCategoryNav() {
		const savedCategory = localStorage.getItem('luci-menu-category') || 'basic';
		
		const isWide = this.isWideScreen();
		
		if (isWide) {
			const titleText = 'FanchmWrt';
			const brandElement = E('a', { 'class': 'top-navbar-brand', 'href': L.url('admin', 'fwx_dashboard') }, [
				E('span', { 'class': 'top-navbar-title' }, [titleText])
			]);
			brandElement.addEventListener('click', function() {
				localStorage.setItem('luci-menu-category', 'basic');
			});
			
			const createModeItem = (category, title, href) => {
				const item = E('li', {
					'class': 'mode-item' + (savedCategory === category ? ' active' : ''),
					'data-category': category
				}, [
					E('a', { 'href': href }, [
						E('span', { 'class': 'mode-check' }, [
							E('img', { 'src': '/luci-static/fanchmwrt/icons/fwx_check.png', 'alt': '' })
						]),
						E('span', { 'class': 'mode-title' }, [_(title)])
					])
				]);

				item.querySelector('a').addEventListener('click', function() {
					localStorage.setItem('luci-menu-category', category);
				});

				return item;
			};

			const modeMenu = E('div', { 'class': 'top-user-menu top-mode-menu' }, [
				E('button', {
					'class': 'top-user-button top-more-button',
					'type': 'button',
					'aria-label': _('Mode menu')
				}, [
					E('span', { 'class': 'top-more-icon' }, ['⋮'])
				]),
				E('ul', { 'class': 'top-user-dropdown top-mode-dropdown' }, [
					createModeItem('basic', 'Normal Mode', L.url('admin', 'fwx_dashboard')),
					createModeItem('advanced', 'Advanced Mode', L.url('admin', 'status', 'overview'))
				])
			]);

			const userMenu = E('div', { 'class': 'top-user-menu top-profile-menu' }, [
				E('button', {
					'class': 'top-user-button',
					'type': 'button',
					'aria-label': _('User menu')
				}, [
					E('span', { 'class': 'top-user-icon', 'aria-hidden': 'true' })
				]),
				E('ul', { 'class': 'top-user-dropdown top-profile-dropdown' }, [
					E('li', { 'class': 'logout-item' }, [
						E('a', { 'href': '#' }, [_('Logout')])
					])
				])
			]);

			const closeTopMenus = () => {
				userMenu.classList.remove('open');
				modeMenu.classList.remove('open');
			};

			const userBtn = userMenu.querySelector('.top-user-button');
			userBtn.addEventListener('click', function(ev) {
				ev.preventDefault();
				ev.stopPropagation();
				const shouldOpen = !userMenu.classList.contains('open');
				closeTopMenus();
				if (shouldOpen) {
					userMenu.classList.add('open');
				}
			});

			const modeBtn = modeMenu.querySelector('.top-more-button');
			modeBtn.addEventListener('click', function(ev) {
				ev.preventDefault();
				ev.stopPropagation();
				const shouldOpen = !modeMenu.classList.contains('open');
				closeTopMenus();
				if (shouldOpen) {
					modeMenu.classList.add('open');
				}
			});

			const logoutLink = userMenu.querySelector('.logout-item a');
			logoutLink.addEventListener('click', function(ev) {
				ev.preventDefault();
				ev.stopPropagation();
				closeTopMenus();
				window.dispatchEvent(new CustomEvent('logout', {
					detail: { source: 'top-profile-menu' }
				}));
				window.location.href = L.url('admin', 'logout');
			});

			document.addEventListener('click', function(ev) {
				if (!userMenu.contains(ev.target) && !modeMenu.contains(ev.target)) {
					closeTopMenus();
				}
			});

			document.addEventListener('keydown', function(ev) {
				if (ev.key === 'Escape') {
					closeTopMenus();
				}
			});

			const topNavbarContent = E('div', { 'class': 'top-navbar-content' }, [
				brandElement,
				E('div', { 'class': 'top-navbar-right' }, [userMenu, modeMenu])
			]);
			const topNavbar = E('div', { 'class': 'top-navbar' }, [topNavbarContent]);

		const body = document.body;
			const existingNavbar = document.querySelector('.top-navbar');
			if (existingNavbar) {
				existingNavbar.remove();
			}
		if (body.firstChild) {
			body.insertBefore(topNavbar, body.firstChild);
		} else {
			body.appendChild(topNavbar);
		}
		
		setTimeout(() => {
			this.switchCategory(savedCategory);
		}, 100);
		}
	},
	

	renderBreadcrumb(tree) {
		if (L.env.dispatchpath && L.env.dispatchpath.length >= 2 &&
			L.env.dispatchpath[0] === 'admin' && L.env.dispatchpath[1] === 'dashboard') {
			return;
		}

		if (!L.env.dispatchpath || L.env.dispatchpath.length === 0) {
			return;
		}

		const breadcrumbItems = [];
		let currentNode = tree;
		let currentPath = '';

		for (let i = 0; i < L.env.dispatchpath.length && currentNode; i++) {
			const pathSegment = L.env.dispatchpath[i];
			currentPath += (currentPath ? '/' : '') + pathSegment;
			
			if (currentNode.children && currentNode.children[pathSegment]) {
				currentNode = currentNode.children[pathSegment];
				
				if (i === 0 && pathSegment === 'admin') {
					const homeItem = E('li', { 'class': 'home-item' }, [
						E('a', { 'href': '/cgi-bin/luci/admin/fwx_dashboard', 'title': _('Home') }, [
							E('span', { 'class': 'home-icon' }, ['🏠'])
						])
					]);
					breadcrumbItems.push(homeItem);
				} else {
					const breadcrumbItem = E('li', {}, [
						E('span', {}, [_(currentNode.title)])
					]);
					
					breadcrumbItems.push(breadcrumbItem);
				}
			}
		}

		if (breadcrumbItems.length === 0) {
			return;
		}

		const breadcrumbContainer = E('div', { 'class': 'breadcrumb-container' }, [
			E('ol', { 'class': 'breadcrumb' }, breadcrumbItems)
		]);

		const mainContent = document.querySelector('#maincontent') || document.querySelector('.main');
		if (mainContent) {
			const existingBreadcrumb = mainContent.querySelector('.breadcrumb-container');
			if (existingBreadcrumb) {
				existingBreadcrumb.remove();
			}
			
			mainContent.insertBefore(breadcrumbContainer, mainContent.firstChild);
		}
	},

	switchCategory(category) {
		
		const isWide = this.isWideScreen();
		if (!isWide) {
			return;
		}
		
		const navTabs = document.querySelector('.top-navbar .nav-tabs');
		if (navTabs) {
			const tabs = navTabs.querySelectorAll('li');
			tabs.forEach(li => {
			li.classList.remove('active');
		});
			const activeTab = navTabs.querySelector(`li[data-category="${category}"]`);
		if (activeTab) {
			activeTab.classList.add('active');
		}
		}

		const modeItems = document.querySelectorAll('.top-user-dropdown .mode-item');
		modeItems.forEach((item) => {
			const isActive = item.getAttribute('data-category') === category;
			item.classList.toggle('active', isActive);
		});

		const menuContainer = document.querySelector('#topmenu');
		
		if (menuContainer) {
			const menuItems = Array.from(menuContainer.children).filter(child => child.tagName === 'LI');
			menuItems.forEach(li => {
			if (category === 'basic') {
				if (li.classList.contains('menu-item-basic')) {
					li.style.display = 'block';
				} else if (li.classList.contains('menu-item-advanced')) {
					li.style.display = 'none';
				}
			} else if (category === 'advanced') {
				if (li.classList.contains('menu-item-basic')) {
					li.style.display = 'none';
				} else if (li.classList.contains('menu-item-advanced')) {
					li.style.display = 'block';
				}
			}
		});
		}
		
		this.currentCategory = category;
		localStorage.setItem('luci-menu-category', category);
	},

	isAlreadyRendered(tree, level, parentName) {

		
		const treeName = tree.name;
		

		if (level === 1 && parentName) {
			const existingSubmenus = document.querySelectorAll('#topmenu .dropdown-menu a');
			for (let link of existingSubmenus) {
				const href = link.getAttribute('href');
				if (href) {

					const pathMatch = href.match(/\/admin\/([^\/\?#]+)\/([^\/\?#]+)/);
					if (pathMatch) {
						const existingParentMenu = pathMatch[1];
						const existingChildMenu = pathMatch[2];
		
						if (existingParentMenu === parentName && existingChildMenu === treeName) {
							return true;
						}
					}
				}
			}
		}

		if (L.env.dispatchpath && L.env.dispatchpath.length > 0) {
			let treeIndex = -1;
			for (let i = 0; i < L.env.dispatchpath.length; i++) {
				if (L.env.dispatchpath[i] === treeName) {
					treeIndex = i;
					break;
				}
			}

			if (treeIndex > 2) {
				return true;
			}
		}
		
		return false;
	},



	getMenuCategory(menuName) {
		const basicMenus = [
			'fwx_dashboard',    
			'fwx_parental_control',
			'fwx_user',
			'fwx_internet_record',
			'fwx_advance',    
			'fwx_network',
			'fwx_session_stat',
			'fwx_user_record',
			'fwx_monitor',
		];

		const normalizedName = (menuName || '').toLowerCase();
		const normalizedBasicMenus = basicMenus.map(m => m.toLowerCase());
		
		if (normalizedBasicMenus.includes(normalizedName)) {
			return 'menu-item-basic';
		} else {
			return 'menu-item-advanced';
		}
	},

	renderTabMenu(tree, url, level) {
		level = level || 0;
		
		const container = document.querySelector('#tabmenu');
		const ul = E('ul', { 'class': 'tabs' });
		const children = ui.menu.getChildren(tree);
		let activeNode = null;

		children.forEach(child => {
			const isActive = (L.env.dispatchpath[3 + level] == child.name);
			const activeClass = isActive ? ' active' : '';
			const className = 'tabmenu-item-%s %s'.format(child.name, activeClass);

			ul.appendChild(E('li', { 'class': className }, [
				E('a', { 'href': L.url(url, child.name) }, [ _(child.title) ] )]));

			if (isActive)
				activeNode = child;
		});

		if (ul.children.length == 0)
			return E([]);

		container.appendChild(ul);
		container.style.display = '';

		if (activeNode)
			this.renderTabMenu(activeNode, url + '/' + activeNode.name, level + 1);

		return ul;
	},

	renderMainMenu(tree, url, level) {
		level = level || 0;

		const isWide = this.isWideScreen();
		let ul;
		
		if (level === 0) {
			if (isWide) {
				ul = document.querySelector('#topmenu');
			} else {
				ul = document.querySelector('#topmenu-mobile');
				if (!ul) {
					const topNavbar = document.querySelector('.top-navbar');
					if (topNavbar) {
						const topNavbarContent = topNavbar.querySelector('.top-navbar-content');
						if (topNavbarContent) {
							ul = topNavbarContent.querySelector('#topmenu-mobile');
							if (!ul) {
								ul = E('ul', { 'id': 'topmenu-mobile', 'class': 'nav navbar-nav' });
								topNavbarContent.appendChild(ul);
							}
						}
					}
				}
				if (!ul) {
					ul = document.querySelector('#topmenu');
				}
			}
		} else {
			ul = E('ul', { 'class': 'dropdown-menu' });
		}
		
		const children = ui.menu.getChildren(tree);

		if (children.length == 0 || level > 1)
			return E([]);

		const parentName = (level === 1) ? tree.name : null;
		if (this.isAlreadyRendered(tree, level, parentName)) {
			return E([]);
		}


		children.forEach(child => {

			const submenu = this.renderMainMenu(child, url + '/' + child.name, level + 1);
			const subclass = (level === 0 && submenu.firstElementChild) ? 'dropdown' : '';
			const linkclass = (level === 0 && submenu.firstElementChild) ? 'menu' : '';
			const linkurl = submenu.firstElementChild ? '#' : L.url(url, child.name);

			const categoryClass = this.getMenuCategory(child.name);
			const classParts = [];
			if (subclass) classParts.push(subclass);
			if (categoryClass) classParts.push(categoryClass);
			const fullClass = classParts.join(' ');

			const iconClass = level === 0 ? this.generateMenuIconClass(child.name) : '';
			const finalLinkClass = linkclass + (iconClass ? ' ' + iconClass : '');
			
			const li = E('li', { 'class': fullClass }, [
				E('a', { 'class': finalLinkClass, 'href': linkurl }, [_(child.title)]),
				submenu
			]);

			if (level === 0 && submenu.firstElementChild) {
				const isActive = ((L.env.dispatchpath[1] == child.name) && (L.env.dispatchpath[0] == tree.name));
				if (isActive) {
					li.classList.add('active', 'open');
				}
			}

		
			if (level === 1) {
				const isActive = ((L.env.dispatchpath[2] == child.name) && (L.env.dispatchpath[1] == tree.name));
				if (isActive) {
					li.classList.add('active');
		
				}
			}


			if (level === 0 && submenu.firstElementChild) {
				const menuLink = li.querySelector('a.menu');
				menuLink.addEventListener('click', function(e) {
					e.preventDefault();
					e.stopPropagation();
					const dropdown = li;
					const isOpen = dropdown.classList.contains('open');
										
	
					const menuSelector = isWide ? '#topmenu' : '#topmenu-mobile';
					document.querySelectorAll(menuSelector + ' .dropdown.open').forEach(item => {
						if (item !== dropdown) {
							item.classList.remove('open');
						}
					});
					

					if (isOpen) {
						dropdown.classList.remove('open');
	
					} else {
						dropdown.classList.add('open');
					}
				});
			}


			if (level === 1) {
				const submenuLink = li.querySelector('a');
				if (submenuLink) {
					submenuLink.addEventListener('click', function(e) {
						e.stopPropagation();
	
						if (!this.isWideScreen()) {
							this.hideMobileMenu();
						}
					}.bind(this));
				}
			}
			

			if (level === 0 && !submenu.firstElementChild) {
				const menuLink = li.querySelector('a');
				if (menuLink) {
					menuLink.addEventListener('click', function(e) {

						if (!this.isWideScreen()) {
							this.hideMobileMenu();
						}
					}.bind(this));
				}
			}

			ul.appendChild(li);
		});

		ul.style.display = '';

		return ul;
	},

	renderMobileMenu(tree, url, level) {
		level = level || 0;
		
		let ul;
		
		if (level === 0) {
	
			ul = document.querySelector('#topmenu-mobile');
			if (!ul) {

				console.error('topmenu-mobile not found in header!');
				return E([]);
			}
		} else {

			ul = E('ul', { 'class': 'dropdown-menu' });
		}
		
		const children = ui.menu.getChildren(tree);

		if (children.length == 0 || level > 1)
			return E([]);
		

		const parentName = (level === 1) ? tree.name : null;
		if (this.isAlreadyRendered(tree, level, parentName)) {
			return E([]);
		}

		children.forEach(child => {


			const submenu = this.renderMobileMenu(child, url + '/' + child.name, level + 1);
			const subclass = (level === 0 && submenu.firstElementChild) ? 'dropdown' : '';
			const linkclass = (level === 0 && submenu.firstElementChild) ? 'menu' : '';
			const linkurl = submenu.firstElementChild ? '#' : L.url(url, child.name);

			const fullClass = subclass;

		
			const iconClass = level === 0 ? this.generateMenuIconClass(child.name) : '';
			const finalLinkClass = linkclass + (iconClass ? ' ' + iconClass : '');
			
			const li = E('li', { 'class': fullClass }, [
				E('a', { 'class': finalLinkClass, 'href': linkurl }, [_(child.title)]),
				submenu
			]);


			if (level === 0 && submenu.firstElementChild) {
				const isActive = ((L.env.dispatchpath[1] == child.name) && (L.env.dispatchpath[0] == tree.name));
				if (isActive) {
					li.classList.add('active', 'open');
				}
			}

	
			if (level === 1) {
				const isActive = ((L.env.dispatchpath[2] == child.name) && (L.env.dispatchpath[1] == tree.name));
				if (isActive) {
					li.classList.add('active');
				}
			}

			if (level === 0 && submenu.firstElementChild) {
				const menuLink = li.querySelector('a.menu');
				menuLink.addEventListener('click', function(e) {
					e.preventDefault();
					e.stopPropagation();
					const dropdown = li;
					const isOpen = dropdown.classList.contains('open');
					

					document.querySelectorAll('#topmenu-mobile .dropdown.open').forEach(item => {
						if (item !== dropdown) {
							item.classList.remove('open');
						}
					});

					if (isOpen) {
						dropdown.classList.remove('open');
					} else {
						dropdown.classList.add('open');
					}
				});
			}

			ul.appendChild(li);
		});

		if (ul && level === 0) {
			ul.style.display = '';
		}

		return ul;
	},

	renderModeMenu(tree) {
		const ul = document.querySelector('#modemenu');
		if (!ul) {
			return;
		}
		ul.innerHTML = '';
		const children = ui.menu.getChildren(tree);

		const isWide = this.isWideScreen();
		if (isWide) {
			ul.style.display = 'none';
		}

		children.forEach((child, index) => {
			const isActive = L.env.requestpath.length
				? child.name === L.env.requestpath[0]
				: index === 0;

			if (!isWide) {
				ul.appendChild(E('li', { 'class': isActive ? 'active' : '' }, [
					E('a', { 'href': L.url(child.name) }, [ _(child.title) ])
				]));
			}

			if (isActive) {

				if (isWide) {
				this.renderMainMenu(child, child.name);
				} else {
					this.renderMobileMenu(child, child.name);
				}
			}
		});

		if (!isWide && ul.children.length > 1)
			ul.style.display = '';

		setTimeout(() => {
			this.autoExpandActiveMenu();
		}, 100);
	},

	autoExpandActiveMenu() {
		const currentPath = L.env.requestpath.join('/');
		const menuItems = document.querySelectorAll('#topmenu .dropdown');
		
		menuItems.forEach(menuItem => {
			const menuLink = menuItem.querySelector('a.menu');
			const menuText = menuLink.textContent.trim();
			
			if (currentPath.includes(menuText.toLowerCase()) || 
				this.isCurrentMenuActive(menuItem, currentPath)) {
				menuItem.classList.add('open');
			}
		});


	},

	isCurrentMenuActive(menuItem, currentPath) {
		const submenuLinks = menuItem.querySelectorAll('.dropdown-menu a');
		for (let link of submenuLinks) {
			const href = link.getAttribute('href');
			if (href && currentPath.includes(href.replace('#', ''))) {
				return true;
			}
		}
		return false;
	}
});
