package client

import (
	"context"
	"fmt"
	"io"
	"math/rand"
	"mime/multipart"
	"os"
	"path/filepath"
	"time"

	"github.com/elastic/go-elasticsearch/v8"

	"xops-admin/domain"
	domain_user_auth "xops-admin/domain/user/auth"
	domain_client "xops-admin/domain/user/client"
	"xops-admin/model"
)

type ClientUserRepo struct {
	clientRepo domain.ClientRepository
	userRepo   domain.UserRepository
}

func (c *ClientUserRepo) GetDomainByClientID(id string) (*model.DomainClient, error) {
	return c.clientRepo.GetDomainByClientID(id)
}

func NewClientUseCase(clientRepo domain.ClientRepository, userRepo domain.UserRepository) domain_client.ClientUseCase {
	return &ClientUserRepo{
		clientRepo: clientRepo,
		userRepo:   userRepo,
	}
}

func (c *ClientUserRepo) GetClientWithLastPentest(clientID, domain string, es *elasticsearch.Client) (*domain_client.ClientPenTestInfo, error) {
	return c.clientRepo.GetClientWithLastPentest(context.TODO(), clientID, domain, es)
}

func (c *ClientUserRepo) CreateUserClient(req *domain_client.CreateClientRequest) (*domain_client.ClientResponse, error) {

	existingUser, err := c.userRepo.FindUserBYEmail(req.Email)
	if err == nil && existingUser != nil {

		existingClient, err := c.clientRepo.GetClientByUserID(existingUser.Id)
		if err == nil && existingClient != nil {

			return c.handleExistingClientDomainUpdate(existingClient, req)
		}
	}

	startDate, err := time.Parse("2006-01-02", req.StartDate)
	if err != nil {
		return nil, fmt.Errorf("invalid start date format: %w", err)
	}

	endDate, err := time.Parse("2006-01-02", req.EndDate)
	if err != nil {
		return nil, fmt.Errorf("invalid end date format: %w", err)
	}

	generatedPassword := c.generateRandomPassword()

	var logoPath string
	if req.Logo != nil {
		logoPath, err = c.saveLogoFile(req.Logo, fmt.Sprintf("temp_%d", time.Now().Unix()))
		if err != nil {
			return nil, fmt.Errorf("failed to save logo: %w", err)
		}
	}

	userWithClientReq := &domain_user_auth.CreateUserWithClientRequest{
		Email:       req.Email,
		IdRole:      3,
		IsVerified:  req.IsVerified,
		IsTwoFA:     req.IsTwoFA,
		LogoCompany: logoPath,
		CompanyName: req.CompanyName,
		StartDate:   startDate,
		EndDate:     endDate,
		Domains:     req.Domains,
		Password:    generatedPassword,
	}

	if err := c.userRepo.CreateUser(userWithClientReq); err != nil {

		if logoPath != "" {
			os.Remove(filepath.Join("public/static", logoPath))
		}
		return nil, fmt.Errorf("failed to create user and client: %w", err)
	}

	user, err := c.userRepo.FindUserBYEmail(req.Email)
	if err != nil {
		return nil, fmt.Errorf("failed to find created user: %w", err)
	}

	client, err := c.clientRepo.GetClientByUserID(user.Id)
	if err != nil {
		return nil, fmt.Errorf("failed to find created client: %w", err)
	}

	if logoPath != "" {
		newLogoPath, err := c.renameLogoFile(logoPath, client.Id)
		if err != nil {

			fmt.Printf("Warning: failed to rename logo file: %v\n", err)
		} else {

			client.LogoCompany = newLogoPath
			c.clientRepo.UpdateClient(client)
		}
	}

	file := "password.html"
	temp := "templates/new_password"
	emailData := domain.EmailData{
		FirstName: user.Name,
		Data:      generatedPassword,
		Subject:   "Your password",
	}
	go domain.SendEmail(user, user.Email, &emailData, file, temp)

	response := &domain_client.ClientResponse{
		User:     user,
		Client:   client,
		Password: generatedPassword,
	}

	return response, nil
}

func (c *ClientUserRepo) handleExistingClientDomainUpdate(existingClient *model.Client, req *domain_client.CreateClientRequest) (*domain_client.ClientResponse, error) {
	// Buat map dari domain yang sudah ada
	existingDomains := make(map[string]bool)
	for _, domainClient := range existingClient.DomainClient {
		existingDomains[domainClient.Domain] = true
	}

	// Cari domain baru yang belum ada
	var newDomains []string
	for _, domain := range req.Domains {
		if !existingDomains[domain] {
			newDomains = append(newDomains, domain)
		}
	}

	// Jika ada domain baru, tambahkan dan simpan ke database
	if len(newDomains) > 0 {
		for _, domain := range newDomains {
			domainClient := model.DomainClient{
				Id:        fmt.Sprintf("domain_%s_%d", existingClient.Id, time.Now().UnixNano()),
				IdClient:  existingClient.Id,
				Domain:    domain,
				Active:    true,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			existingClient.DomainClient = append(existingClient.DomainClient, domainClient)
		}

		// TAMBAHAN: Simpan perubahan ke database
		if err := c.clientRepo.UpdateClient(existingClient); err != nil {
			return nil, fmt.Errorf("failed to update client with new domains: %w", err)
		}
	}

	user, err := c.userRepo.FindUserBYID(existingClient.IdUser)
	if err != nil {
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	response := &domain_client.ClientResponse{
		User:     user,
		Client:   existingClient,
		Password: "",
	}

	return response, nil
}
func (c *ClientUserRepo) generateRandomPassword() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	const randomLength = 5

	rand.Seed(time.Now().UnixNano())
	randomPart := make([]byte, randomLength)
	for i := range randomPart {
		randomPart[i] = charset[rand.Intn(len(charset))]
	}

	return "Default_password1" + string(randomPart)
}

func (c *ClientUserRepo) UpdateUserClient(id string, req *domain_client.UpdateClientRequest) error {

	existingClient, err := c.clientRepo.GetClientByID(id)
	if err != nil {
		return fmt.Errorf("client not found: %w", err)
	}

	if req.CompanyName != "" {
		existingClient.CompanyName = req.CompanyName
	}

	if req.StartDate != "" {
		startDate, err := time.Parse("2006-01-02", req.StartDate)
		if err != nil {
			return fmt.Errorf("invalid start date format: %w", err)
		}
		existingClient.StartDate = startDate
	}

	if req.EndDate != "" {
		endDate, err := time.Parse("2006-01-02", req.EndDate)
		if err != nil {
			return fmt.Errorf("invalid end date format: %w", err)
		}
		existingClient.EndDate = endDate
	}

	if req.Logo != nil {

		if existingClient.LogoCompany != "" {
			oldLogoPath := filepath.Join("public/static", existingClient.LogoCompany)
			os.Remove(oldLogoPath)
		}

		logoPath, err := c.saveLogoFile(req.Logo, id)
		if err != nil {
			return fmt.Errorf("failed to save logo: %w", err)
		}
		existingClient.LogoCompany = logoPath
	}

	if req.Email != "" {
		user, err := c.userRepo.FindUserBYID(existingClient.IdUser)
		if err != nil {
			return fmt.Errorf("failed to find user: %w", err)
		}
		user.Email = req.Email
		if err := c.userRepo.UpdateUser(user); err != nil {
			return fmt.Errorf("failed to update user email: %w", err)
		}
	}

	if len(req.Domains) > 0 {

		existingClient.DomainClient = []model.DomainClient{}

		for _, domain := range req.Domains {
			fmt.Println(domain)
			domainClient := model.DomainClient{
				Id:        fmt.Sprintf("domain_%s_%d", id, time.Now().UnixNano()),
				IdClient:  id,
				Domain:    domain,
				Active:    true,
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			existingClient.DomainClient = append(existingClient.DomainClient, domainClient)
		}
	}

	return c.clientRepo.UpdateClient(existingClient)
}

func (c *ClientUserRepo) saveLogoFile(fileHeader *multipart.FileHeader, clientID string) (string, error) {

	staticDir := "public/static"
	if err := os.MkdirAll(staticDir, 0755); err != nil {
		return "", fmt.Errorf("failed to create static directory: %w", err)
	}

	ext := filepath.Ext(fileHeader.Filename)
	if ext == "" {
		ext = ".jpg"
	}

	filename := fmt.Sprintf("logo_%s_%d%s", clientID, time.Now().Unix(), ext)
	filePath := filepath.Join(staticDir, filename)

	src, err := fileHeader.Open()
	if err != nil {
		return "", fmt.Errorf("failed to open uploaded file: %w", err)
	}
	defer src.Close()

	dst, err := os.Create(filePath)
	if err != nil {
		return "", fmt.Errorf("failed to create destination file: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return "", fmt.Errorf("failed to save file: %w", err)
	}

	return filename, nil
}

func (c *ClientUserRepo) renameLogoFile(oldPath, clientID string) (string, error) {
	if oldPath == "" {
		return "", nil
	}

	oldFilePath := filepath.Join("public/static", oldPath)

	ext := filepath.Ext(oldPath)
	if ext == "" {
		ext = ".jpg"
	}

	newFilename := fmt.Sprintf("logo_%s_%d%s", clientID, time.Now().Unix(), ext)
	newFilePath := filepath.Join("public/static", newFilename)

	if err := os.Rename(oldFilePath, newFilePath); err != nil {
		return "", fmt.Errorf("failed to rename file: %w", err)
	}

	return newFilename, nil
}
