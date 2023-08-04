# testrepository
package com.thinkfully.service;

import static com.thinkfully.util.MessagePropertyConstant.DASHBOARD_BOARDNAME;
import static com.thinkfully.util.MessagePropertyConstant.DASHBOARD_DEFAULT;
import static com.thinkfully.util.MessagePropertyConstant.DASHBOARD_PREVIEW_IMAGE_URL;
import static com.thinkfully.util.MessagePropertyConstant.DASHBOARD_VERSION_CREATED_DATE;
import static com.thinkfully.util.MessagePropertyConstant.DASHBOARD_VERSION_ID;
import static com.thinkfully.util.MessagePropertyConstant.ERROR_DASHBOARD_NOT_FOUND;
import static com.thinkfully.util.MessagePropertyConstant.ERROR_DASHBOARD_VERSION_NOT_FOUND;
import static com.thinkfully.util.MessagePropertyConstant.ERROR_GLOBAL_INTERNAL_SERVER_EXCEPTION;
import static com.thinkfully.util.MessagePropertyConstant.ERROR_USER_ALREADY_EXIST;
import static com.thinkfully.util.MessagePropertyConstant.ERROR_USER_CONFIRM_PASSWORD_NOT_MATCHED;
import static com.thinkfully.util.MessagePropertyConstant.ERROR_USER_GET_DETAILS_FAILED;
import static com.thinkfully.util.MessagePropertyConstant.ERROR_USER_INVALID_RESET_TOKEN;
import static com.thinkfully.util.MessagePropertyConstant.ERROR_USER_INVITECODE_INVALID;
import static com.thinkfully.util.MessagePropertyConstant.ERROR_USER_LOGIN_FAILED;
import static com.thinkfully.util.MessagePropertyConstant.ERROR_USER_NOT_ACTIVE;
import static com.thinkfully.util.MessagePropertyConstant.ERROR_USER_NOT_FOUND;
import static com.thinkfully.util.MessagePropertyConstant.ERROR_USER_OLD_PASSWORD_NOT_MATCHED;
import static com.thinkfully.util.MessagePropertyConstant.ERROR_USER_PASSWORD_INVALID;
import static com.thinkfully.util.MessagePropertyConstant.ERROR_USER_RESET_PASSWORD_TOKEN_INVALID;
import static com.thinkfully.util.MessagePropertyConstant.ERROR_USER_RESET_PASSWORD_TOKEN_NOT_GENERATED;
import static com.thinkfully.util.MessagePropertyConstant.ERROR_USER_USERNAME_INVALID;
import static com.thinkfully.util.MessagePropertyConstant.INFO_DASHBOARD_LIMIT_REACHED;
import static com.thinkfully.util.MessagePropertyConstant.INFO_GLOBAL_SUCCESS_MESSAGE;
import static com.thinkfully.util.MessagePropertyConstant.INFO_USER_CHANGE_PASSWORD_SUCCESS;
import static com.thinkfully.util.MessagePropertyConstant.INFO_USER_CREATED;
import static com.thinkfully.util.MessagePropertyConstant.INFO_USER_LOGIN_SUCCESS;
import static com.thinkfully.util.MessagePropertyConstant.INFO_USER_MAIL_SUBJECT_PASSWORD_RESET_REQUEST;
import static com.thinkfully.util.MessagePropertyConstant.INFO_USER_RESET_PASSWORD_SUCCESS;
import static com.thinkfully.util.MessagePropertyConstant.INFO_USER_RESET_PASSWORD_TOKEN_VALID;
import static com.thinkfully.util.MessagePropertyConstant.INFO_USER_SAVE_DASHBOARD_DATA;
import static com.thinkfully.util.MessagePropertyConstant.INFO_USER_SUCCESS_MAIL_SEND;
import static com.thinkfully.util.MessagePropertyConstant.PROPERTY_DASHBOARD_AUTOTITLE;
import static com.thinkfully.util.MessagePropertyConstant.PROPERTY_GOLDEN_NUGGET;
import static com.thinkfully.util.MessagePropertyConstant.PROPERTY_TITLE;
import static com.thinkfully.util.MessagePropertyConstant.SUCCESS_CLEANUP_MESSAGE;
import static com.thinkfully.util.MessagePropertyConstant.SUCCESS_DASHBOARD_DELETED;
import static com.thinkfully.util.MessagePropertyConstant.SUCCESS_DASHBOARD_FOUND;
import static com.thinkfully.util.MessagePropertyConstant.SUCCESS_DASHBOARD_VERSION_FOUND;
import static com.thinkfully.util.MessagePropertyConstant.ERROR_DELETE_FILE;

import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import javax.servlet.http.HttpServletRequest;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.modelmapper.ModelMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.dao.DataAccessResourceFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.thinkfully.dto.BoardShareResponse;
import com.thinkfully.dto.ChangePasswordDto;
import com.thinkfully.dto.DashboardResponse;
import com.thinkfully.dto.PasswordResetResponse;
import com.thinkfully.dto.RestResponse;
import com.thinkfully.dto.UserDto;
import com.thinkfully.model.BoardShare;
import com.thinkfully.model.BoardTitle;
import com.thinkfully.model.DashBoardVersion;
import com.thinkfully.model.PasswordResetKey;
import com.thinkfully.model.User;
import com.thinkfully.model.UserActivity;
import com.thinkfully.model.UserDashBoard;
import com.thinkfully.model.UserListResponse;
import com.thinkfully.repository.BoardShareRepo;
import com.thinkfully.repository.DashBoardVersionRepo;
import com.thinkfully.repository.PasswordResetKeyRepo;
import com.thinkfully.repository.UserActivityContentRepo;
import com.thinkfully.repository.UserActivityRepo;
import com.thinkfully.repository.UserDashBoardRepo;
import com.thinkfully.repository.UserRepo;
import com.thinkfully.util.Helper;
import com.thinkfully.util.JsonUtil;
import com.thinkfully.util.MessagePropertyConstant;

import lombok.extern.slf4j.Slf4j;

@Slf4j
@Service
public class UserService {


	@Autowired
	UserRepo userRepo;

	@Autowired
	PasswordResetKeyRepo passwordResetKeyRepo;

	@Autowired
	UserDashBoardRepo userDashBoardRepo;

	@Autowired
	BoardShareRepo boardShareRepo;

	@Autowired
	DashBoardVersionRepo boardVersionRepo;

	@Autowired
	UserActivityRepo usrActivityRepo;

	@Autowired
	UserActivityContentRepo usrActivityContentRepo;

	@Autowired
	Helper helper;

	@Autowired
	ModelMapper modelMapper;

	@Autowired
	GrabScrnService picService;

	@Autowired
	AdminService adminServie;

	@Value("${inviteCode}")
	String validCode;

	@Value("${dashboardLimit}")
	String dashboardLimit;

	@Value("${MessageTitle}")
	String messageTitle;

	@Value("${resetpassword.mailfrom}")
	String resetPasswordMail;

	@Value("${previewImage.format}")
	String previewImageFormat;

	public ResponseEntity<RestResponse> createUser(User user) {
		RestResponse response = new RestResponse();
		try {
			String inviteCode = user.getInviteCode();
			if (!helper.checkInviteCode(inviteCode, validCode)) {
				log.error(helper.message(ERROR_USER_INVITECODE_INVALID));
				response.setMessage(helper.message(ERROR_USER_INVITECODE_INVALID));
				return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);

			}

			String userName = (user.getUserName()).toLowerCase();
			user.setUserName(userName);
			String password = user.getPassword();
			String confirmPassword = user.getConfirmPassword();

			if (userRepo.existsByUserName(userName)) {
				log.error(helper.message(ERROR_USER_ALREADY_EXIST));
				response.setMessage(helper.message(ERROR_USER_ALREADY_EXIST));
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
			}
			if (!helper.isValidEmail(userName)) {
				log.error(helper.message(ERROR_USER_USERNAME_INVALID));
				response.setMessage(helper.message(ERROR_USER_USERNAME_INVALID));
				return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
			}
			if (!helper.isValidPassword(password)) {
				log.error(helper.message(ERROR_USER_PASSWORD_INVALID));
				response.setMessage(helper.message(ERROR_USER_PASSWORD_INVALID));
				return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
			}
			if (!helper.isConfirmPassEqualsPassword(password, confirmPassword)) {
				log.error(helper.message(ERROR_USER_CONFIRM_PASSWORD_NOT_MATCHED));
				response.setMessage(helper.message(ERROR_USER_CONFIRM_PASSWORD_NOT_MATCHED));
				return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(response);
			}
			user.setPassword(helper.passwordEncryption(password));
			User newRecord = userRepo.save(user);
			response.setMessage(helper.message(INFO_USER_CREATED));
			// convert entity to DTO
			UserDto userResponse = modelMapper.map(newRecord, UserDto.class);
			response.setData(userResponse);
			response.setStatus(true);
			return ResponseEntity.status(HttpStatus.CREATED).body(response);
		} catch (NoSuchAlgorithmException | DataAccessResourceFailureException e) {
			response.setMessage(helper.message(ERROR_GLOBAL_INTERNAL_SERVER_EXCEPTION));
			log.error("Exception at user creation: {}", e.getMessage());
			return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(response);
		}
	}

	public ResponseEntity<RestResponse> login(User userLogin) {
		RestResponse restResponse = new RestResponse();
		try {
			String username = userLogin.getUserName().toLowerCase();
			String password = userLogin.getPassword();
			password = helper.passwordEncryption(password);
			Optional<User> userRecord = userRepo.findFirstByUserName(username);
			User user = userRecord.orElse(null);

			if (!userRecord.isPresent()) {
				log.debug("user not found");
				restResponse.setMessage(helper.message(ERROR_USER_NOT_FOUND));
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(restResponse);
			} else if (userRecord.orElse(null) != null && userRecord.orElse(null).isArchive()) {
				log.debug("user archived");
				restResponse.setMessage(helper.message(ERROR_USER_NOT_ACTIVE));
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(restResponse);
			}

			if (userRepo.findFirstByUserNameAndPassword(username, password) != null && user != null) {
				String userToken = helper.generateToken(username, password);
				restResponse.setMessage(helper.message(INFO_USER_LOGIN_SUCCESS));
				restResponse.setToken(userToken);
				restResponse.setStatus(true);
				restResponse.setRolesList(getRoleListByUser(user));
				restResponse.setNewUser(isNewUser(username));
				return ResponseEntity.status(HttpStatus.OK).body(restResponse);
			} else {
				log.error(helper.message(ERROR_USER_LOGIN_FAILED));
				restResponse.setMessage(helper.message(ERROR_USER_LOGIN_FAILED));
				return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(restResponse);
			}
		} catch (NoSuchAlgorithmException | DataAccessResourceFailureException e) {
			restResponse.setMessage(helper.message(ERROR_GLOBAL_INTERNAL_SERVER_EXCEPTION));
			e.printStackTrace();
			log.error("Exception at login: {}", e.getMessage());
			return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(restResponse);
		}
	}

	public RestResponse getAll() {
		RestResponse restResponse = new RestResponse();
		try {
			List<User> user = userRepo.findAll();
			List<UserDto> userDto = helper.convertInUserDto(user);
			restResponse.setData(userDto);
			if (!userDto.isEmpty()) {
				restResponse.setMessage(helper.message(INFO_GLOBAL_SUCCESS_MESSAGE));
				restResponse.setStatus(true);
				return restResponse;
			} else {
				restResponse.setMessage(helper.message(ERROR_USER_GET_DETAILS_FAILED));
				return restResponse;
			}
		} catch (DataAccessResourceFailureException e) {
			restResponse.setMessage(helper.message(ERROR_GLOBAL_INTERNAL_SERVER_EXCEPTION));
			e.printStackTrace();
			log.error("Exception when interact with database: {}", e.getMessage());
			return restResponse;
		}
	}

	public ResponseEntity<RestResponse> forgotPasswordMailSend(String userName, HttpServletRequest request) {
		RestResponse response = new RestResponse();

		try {

			userName = userName.toLowerCase();
			boolean exist = userRepo.existsByUserName(userName);

			if (exist) {
				String token = UUID.randomUUID().toString();
				PasswordResetKey tokenKey = new PasswordResetKey(userName, token);
				PasswordResetKey key = passwordResetKeyRepo.save(tokenKey);

				if (key != null) {
					String appUrl = helper.getSiteURL(request);
					// Email message

					helper.mailSender(resetPasswordMail, userName,
							helper.message(INFO_USER_MAIL_SUBJECT_PASSWORD_RESET_REQUEST),
							"To reset your password, click the link below:\n" + appUrl + "?token=" + token);
					response.setMessage(helper.message(INFO_USER_SUCCESS_MAIL_SEND));
					response.setStatus(true);
					return ResponseEntity.status(HttpStatus.OK).body(response);
				} else {
					log.error(helper.message(ERROR_USER_RESET_PASSWORD_TOKEN_NOT_GENERATED));
					response.setMessage(helper.message(ERROR_USER_RESET_PASSWORD_TOKEN_NOT_GENERATED));
					return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
				}
			} else {
				log.error(helper.message(ERROR_USER_NOT_FOUND));
				response.setMessage(helper.message(ERROR_USER_NOT_FOUND));
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
			}
		} catch (DataAccessResourceFailureException e) {
			log.error(helper.message(ERROR_GLOBAL_INTERNAL_SERVER_EXCEPTION), e.getMessage());
			response.setMessage(helper.message(ERROR_GLOBAL_INTERNAL_SERVER_EXCEPTION));
			return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(response);
		}
	}

	public ResponseEntity<RestResponse> validatePasswordResetToken(String token) {

		RestResponse response = new RestResponse();
		try {
			PasswordResetKey resetKey = passwordResetKeyRepo.findByResetToken(token);
			if (resetKey != null) {
				response.setData(resetKey.getUserName());
				response.setMessage(helper.message(INFO_USER_RESET_PASSWORD_TOKEN_VALID));
				response.setStatus(true);
				return ResponseEntity.status(HttpStatus.OK).body(response);
			} else {
				log.error(helper.message(ERROR_USER_RESET_PASSWORD_TOKEN_INVALID));
				response.setMessage(helper.message(ERROR_USER_RESET_PASSWORD_TOKEN_INVALID));
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
			}

		} catch (DataAccessResourceFailureException e) {
			log.error(helper.message(ERROR_GLOBAL_INTERNAL_SERVER_EXCEPTION), e.getMessage());
			response.setMessage(helper.message(ERROR_GLOBAL_INTERNAL_SERVER_EXCEPTION));
			return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(response);
		}

	}

	public ResponseEntity<RestResponse> updatePassword(PasswordResetResponse updatePassword) {
		RestResponse response = new RestResponse();
		try {
			String newPassword = updatePassword.getPassword();
			String confirmPassword = updatePassword.getConfirmPassword();
			String token = updatePassword.getToken();

			PasswordResetKey resetKey = passwordResetKeyRepo.findByResetToken(token);

			if (resetKey == null) {
				log.error(helper.message(ERROR_USER_INVALID_RESET_TOKEN));
				response.setMessage(helper.message(ERROR_USER_INVALID_RESET_TOKEN));
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
			}

			String userName = resetKey.getUserName();

			if (!helper.isValidPassword(newPassword)) {
				log.error(helper.message(ERROR_USER_PASSWORD_INVALID));
				response.setMessage(helper.message(ERROR_USER_PASSWORD_INVALID));
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
			}
			if (!helper.isConfirmPassEqualsPassword(newPassword, confirmPassword)) {
				log.error(helper.message(ERROR_USER_CONFIRM_PASSWORD_NOT_MATCHED));
				response.setMessage(helper.message(ERROR_USER_CONFIRM_PASSWORD_NOT_MATCHED));
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
			}
			
			userName = userName.toLowerCase();
			Optional<User> userRecord = userRepo.findFirstByUserName(userName);
			User user = userRecord.orElse(null);

			if (userRecord.isPresent() && user!= null) {
				user.setPassword(helper.passwordEncryption(newPassword));
				userRepo.save(user);
				passwordResetKeyRepo.deleteByUserName(userName);
				response.setMessage(helper.message(INFO_USER_RESET_PASSWORD_SUCCESS));
				response.setStatus(true);
				return ResponseEntity.status(HttpStatus.OK).body(response);
			} else {
				log.error(helper.message(ERROR_USER_NOT_FOUND));
				response.setMessage(helper.message(ERROR_USER_NOT_FOUND));
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
			}

		} catch (NoSuchAlgorithmException | DataAccessResourceFailureException e) {
			log.error(helper.message(ERROR_GLOBAL_INTERNAL_SERVER_EXCEPTION), e.getMessage());
			response.setMessage(helper.message(ERROR_GLOBAL_INTERNAL_SERVER_EXCEPTION));
			return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(response);
		}

	}

	public ResponseEntity<RestResponse> changePassword(ChangePasswordDto changePassword) {
		RestResponse response = new RestResponse();
		try {
			String userName = changePassword.getUserName();
			String oldPassword = changePassword.getOldPassword();
			String newPassword = changePassword.getNewPassword();
			String confirmPassword = changePassword.getConfirmPassword();

			if (!helper.isValidPassword(newPassword)) {
				log.error(helper.message(ERROR_USER_PASSWORD_INVALID));
				response.setMessage(helper.message(ERROR_USER_PASSWORD_INVALID));
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
			}
			if (!helper.isConfirmPassEqualsPassword(newPassword, confirmPassword)) {
				log.error(helper.message(ERROR_USER_CONFIRM_PASSWORD_NOT_MATCHED));
				response.setMessage(helper.message(ERROR_USER_CONFIRM_PASSWORD_NOT_MATCHED));
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
			}
			
			userName = userName.toLowerCase();
			Optional<User> userRecord = userRepo.findFirstByUserName(userName);
			User user = userRecord.orElse(null);

			if (user != null) {

				String encrptedOldPassword = helper.passwordEncryption(oldPassword);
				String encrptedStoredPassword = user.getPassword();

				if (!helper.isConfirmPassEqualsPassword(encrptedOldPassword, encrptedStoredPassword)) {
					log.error(helper.message(ERROR_USER_OLD_PASSWORD_NOT_MATCHED));
					response.setMessage(helper.message(ERROR_USER_OLD_PASSWORD_NOT_MATCHED));
					return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
				} else {
					user.setPassword(helper.passwordEncryption(newPassword));
					userRepo.save(user);
					response.setMessage(helper.message(INFO_USER_CHANGE_PASSWORD_SUCCESS));
					response.setStatus(true);
					return ResponseEntity.status(HttpStatus.OK).body(response);
				}
			} else {
				log.error(helper.message(ERROR_USER_NOT_FOUND));
				response.setMessage(helper.message(ERROR_USER_NOT_FOUND));
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
			}
		} catch (DataAccessResourceFailureException | NoSuchAlgorithmException e) {
			log.error(helper.message(ERROR_GLOBAL_INTERNAL_SERVER_EXCEPTION), e.getMessage());
			response.setMessage(helper.message(ERROR_GLOBAL_INTERNAL_SERVER_EXCEPTION));
			return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(response);
		}

	}

	@PreAuthorize(value = "#username == authentication.principal.username || hasRole('ROLE_ADMIN')")
	public ResponseEntity<Object> getListDashboardVersion(String boardID, String username) {

		List<DashBoardVersion> boardList = boardVersionRepo.findByBoardName(boardID);
		if (!boardList.isEmpty()) {
			return ResponseEntity.status(HttpStatus.OK).body(listIntoJsonBoardVersion(boardList).toList());
		} else {
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new JSONArray().toList());
		}
	}

	@PreAuthorize(value = "#username == authentication.principal.username || hasRole('ROLE_ADMIN')")
	public ResponseEntity<Object> getUserDashBoardData(String username) {
		List<UserDashBoard> userDashBoardList = userDashBoardRepo.findByUserName(username);
		if (!userDashBoardList.isEmpty()) {
			return ResponseEntity.status(HttpStatus.OK).body(listIntoJsonDashboard(userDashBoardList).toList());
		} else {
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(new JSONArray().toList());
		}

	}

	@PreAuthorize(value = "#username == authentication.principal.username" + " || hasRole('ROLE_ADMIN')")
	public ResponseEntity<DashboardResponse> getUserDashBoardDataById(String id, String username) {

		DashboardResponse response = new DashboardResponse();
		Optional<UserDashBoard> optionalBoard = userDashBoardRepo.findById(id);
		if (optionalBoard.isPresent()) {
			UserDashBoard board = optionalBoard.get();
			if (board.isArchive()) {
				response.setStatus(false);
				response.setMessage(helper.message(ERROR_DASHBOARD_NOT_FOUND));
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
			}
			userDashBoardRepo.save(board);
			// DashBoardVersion version = getVersionHaveImageFormed(board);
			String previewImageurl = getVersionHaveImageFormed(board);
			response.setData(board.getJson());
			response.setBoardMessage(board.getBoardMessage());
			response.setPreviewImageUrl(helper.hostname + previewImageurl);
			response.setTitle(board.getTitle());
			response.setAutoTitle(board.isAutoTitle());
			response.setGoldenNugget(board.isGoldenNugget());
			response.setBoardName(board.getId());
			response.setStatus(true);
			response.setMessage(helper.message(INFO_GLOBAL_SUCCESS_MESSAGE));
			return ResponseEntity.status(HttpStatus.OK).body(response);
		} else {
			response.setStatus(false);
			response.setMessage(helper.message(ERROR_DASHBOARD_NOT_FOUND));
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
		}
	}

//	@PreAuthorize(value = "#username == authentication.principal.username" + " || hasRole('ROLE_ADMIN')")
	public ResponseEntity<DashboardResponse> getUserDashBoardDataVersionById(String id, String username) {

		DashboardResponse response = new DashboardResponse();
		Optional<DashBoardVersion> optionalBoard = boardVersionRepo.findById(id);
		if (optionalBoard.isPresent()) {
			DashBoardVersion board = optionalBoard.get();
			if (board.isArchive()) {
				response.setStatus(false);
				response.setMessage(helper.message(ERROR_DASHBOARD_VERSION_NOT_FOUND));
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
			}
			response.setBoardName(board.getBoardName());
			response.setData(board.getJson());
			response.setBoardMessage(board.getBoardMessage());
			response.setPreviewImageUrl(helper.hostname + board.getPreviewImageUrl());
			response.setTitle(board.getTitle());
			response.setAutoTitle(board.isAutoTitle());
			response.setGoldenNugget(board.isGoldenNugget());
			response.setStatus(true);
			response.setMessage(helper.message(SUCCESS_DASHBOARD_VERSION_FOUND));
			return ResponseEntity.status(HttpStatus.OK).body(response);
		} else {
			response.setStatus(false);
			response.setMessage(helper.message(ERROR_DASHBOARD_VERSION_NOT_FOUND));
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
		}

	}

	public ResponseEntity<BoardShareResponse> getShareIdByCanvas(BoardShare boardShare) {
		BoardShareResponse response = new BoardShareResponse();

		String boardName = boardShare.getBoardName();
		if (userDashBoardRepo.existsById(boardName)) {
			Optional<UserDashBoard> optBoard = userDashBoardRepo.findById(boardName);
			if (optBoard.isPresent()) {
				UserDashBoard board = optBoard.get();
				if (board.isArchive()) {
					response.setStatus(false);
					response.setMessage("Board not found");
					return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
				}
			}
			Optional<BoardShare> optBoardShare = boardShareRepo.findByBoardName(boardName);
			if (optBoardShare.isPresent()) {
				BoardShare optionalBoardShare = optBoardShare.get();
				if (optionalBoardShare.isArchive()) {
					response.setStatus(false);
					response.setMessage("Board not found");
					return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
				}
				optionalBoardShare.setAccessType(helper.getBoardAccessType(boardShare));
				optionalBoardShare.setUserRef(boardShare.getUserRef());
				boardShareRepo.save(optionalBoardShare);
				response.setShareId(optionalBoardShare.getId());
			} else {
				boardShare.setAccessType(helper.getBoardAccessType(boardShare));
				boardShareRepo.save(boardShare);
				response.setShareId(boardShare.getId());
			}
			response.setStatus(true);
			response.setMessage(helper.message(INFO_GLOBAL_SUCCESS_MESSAGE));
			return ResponseEntity.status(HttpStatus.OK).body(response);
		} else {
			response.setStatus(false);
			response.setMessage(helper.message(ERROR_DASHBOARD_NOT_FOUND));
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
		}
	}

	public ResponseEntity<DashboardResponse> getCanvasIdByShare(String shareId) {
		DashboardResponse response = new DashboardResponse();
		Optional<BoardShare> optionalBoardShare = boardShareRepo.findById(shareId);
		if (optionalBoardShare.isPresent()) {
			BoardShare boardShare = optionalBoardShare.get();
			String boardName = boardShare.getBoardName();
			Optional<UserDashBoard> optionalBoard = userDashBoardRepo.findById(boardName);
			if (optionalBoard.isPresent()) {
				UserDashBoard dashBoard = optionalBoard.get();
				if (dashBoard.isArchive()) {
					response.setStatus(false);
					response.setMessage(helper.message(MessagePropertyConstant.ERROR_DASHBOARD_DELETED));
					return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(response);
				}
				response.setData(dashBoard.getJson());
				response.setBoardMessage(dashBoard.getBoardMessage());
				response.setBoardName(dashBoard.getId());
				response.setGoldenNugget(dashBoard.isGoldenNugget());
				response.setPreviewImageUrl(helper.hostname + dashBoard.getPreviewImageUrl());
				response.setTitle(dashBoard.getTitle());
				response.setStatus(true);
				response.setMessage(helper.message(SUCCESS_DASHBOARD_FOUND));
			}
			return ResponseEntity.status(HttpStatus.OK).body(response);
		} else {
			response.setStatus(false);
			response.setMessage(helper.message(ERROR_DASHBOARD_NOT_FOUND));
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);

		}

	}

	@PreAuthorize(value = "#username == authentication.principal.username" + " || hasRole('ROLE_ADMIN')")
	public ResponseEntity<String> deleteDashboardById(String username, String id) {
		Optional<UserDashBoard> optDashboard = userDashBoardRepo.findById(id);
		if (optDashboard.isPresent()) {
			UserDashBoard board = optDashboard.get();
			board.setArchive(true);
			userDashBoardRepo.save(board);
			return ResponseEntity.status(HttpStatus.OK).body(helper.message(SUCCESS_DASHBOARD_DELETED));
		}
		return ResponseEntity.status(HttpStatus.NOT_FOUND).body(helper.message(ERROR_DASHBOARD_NOT_FOUND));

	}

	@PreAuthorize(value = "#username == authentication.principal.username" + " || hasRole('ROLE_ADMIN')")
	public boolean deleteUser(String username) {

		if (userRepo.existsByUserName(username)) {

			username = username.toLowerCase();
			Optional<User> userRecord = userRepo.findFirstByUserName(username);
			User user = userRecord.orElse(null);

			if (user.isArchive()) {
				return false;
			}
			user.setArchive(true);
			userRepo.save(user);
			return true;
		}
		return false;

	}

	@PreAuthorize(value = "#dashboard.userName == authentication.principal.username" + " || hasRole('ROLE_ADMIN')")
	public ResponseEntity<RestResponse> setDashBoardDataByOp(UserDashBoard dashboard) {

		String operation = dashboard.getOperation();
		try {
			ObjectMapper mapper = new ObjectMapper();
			LinkedHashMap jsonMap = (LinkedHashMap) dashboard.getJson();
			String jsonStr = mapper.writeValueAsString(jsonMap);
			if ("shuffle".equalsIgnoreCase(operation)) {
				Object outputJson = JsonUtil.shuffleBoard(jsonStr);
				dashboard.setJson(outputJson);
			} else if ("sort".equalsIgnoreCase(operation)) {
				Object outputJson = JsonUtil.groupBoardByColor(jsonStr);
				dashboard.setJson(outputJson);
			}

			return setUserDashBoardData(dashboard);

		} catch (IOException | JSONException e) {
			log.error("Exception in method setDashBoardDataByOp");
			e.printStackTrace();
			RestResponse response = new RestResponse();
			response.setMessage(helper.message(ERROR_GLOBAL_INTERNAL_SERVER_EXCEPTION));
			return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(response);
		}
	}

	public boolean changeBoardTitle(BoardTitle board) {
		String id = board.getId();
		Optional<UserDashBoard> optBoard = userDashBoardRepo.findById(id);
		if (optBoard.isPresent()) {
			UserDashBoard dashboard = optBoard.get();
			if (dashboard.isArchive()) {
				return false;
			}
			String username = dashboard.getUserName();
			List<UserDashBoard> userDashBoardList = userDashBoardRepo.findByUserName(username);
			Collections.reverse(userDashBoardList); // reversing the order of dashboard
			dashboard.setTitle(board.getTitle());
			setDashBoardTitle(dashboard, true);

			for (UserDashBoard lboard : userDashBoardList) { // saving dashboard in reverse order for
																// maintaining order of dashboards before
																// changing the title.
				if (Objects.equals(id, lboard.getId())) {
					userDashBoardRepo.save(dashboard);
				} else {
					userDashBoardRepo.save(lboard);
				}
			}
			return true;
		}
		return false;
	}

	public ResponseEntity<RestResponse> setUserDashBoardData(UserDashBoard dashBoard) {
		RestResponse response = new RestResponse();
		DashBoardVersion boardVersion = new DashBoardVersion();
		try {
			String userName = dashBoard.getUserName().toLowerCase();

			UserDashBoard savedDashBoard = null;
			if (userRepo.existsByUserName(userName)) {
				String boardName = dashBoard.getBoardName();
				return saveBoardIfUserExists(boardName, savedDashBoard, dashBoard, boardVersion);
			} else {
				log.error(helper.message(ERROR_USER_NOT_FOUND));
				response.setMessage(helper.message(ERROR_USER_NOT_FOUND));
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
			}
		} catch (

		Exception e) {
			log.error(helper.message(ERROR_GLOBAL_INTERNAL_SERVER_EXCEPTION), e.getMessage());
			response.setMessage(helper.message(ERROR_GLOBAL_INTERNAL_SERVER_EXCEPTION));
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.UNPROCESSABLE_ENTITY).body(response);

		}
	}

	public ResponseEntity<RestResponse> saveBoardIfUserExists(String boardName, UserDashBoard savedDashBoard,
			UserDashBoard dashBoard, DashBoardVersion boardVersion) {
		RestResponse response = new RestResponse();
		String userName = dashBoard.getUserName().toLowerCase();
		if (!boardName.isEmpty()) {

			Optional<UserDashBoard> optionalBoard = userDashBoardRepo.findById(boardName);
			if (optionalBoard.isPresent()) {
				// save dashboard
				savedDashBoard = setBoardProperties(dashBoard, optionalBoard.get());

				response.setBoardName(savedDashBoard.getId());
				response.setData(savedDashBoard.getJson());

				Map<String, Object> contentMap = new HashMap<String, Object>();
				contentMap.put("title", savedDashBoard.getTitle());
				contentMap.put("autoTitle", savedDashBoard.isAutoTitle());
				contentMap.put("boardName", savedDashBoard.getId());
				response.setContent(contentMap);

				boardVersion = saveBoardVersion(savedDashBoard);

			} else {
				if (dashboardLimitReached(userName)) {
					response.setMessage(helper.message(INFO_DASHBOARD_LIMIT_REACHED));
					return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
				}

				setDashBoardTitle(dashBoard, false);
				savedDashBoard = userDashBoardRepo.save(dashBoard);
				response.setBoardName(savedDashBoard.getId());
				response.setData(savedDashBoard.getJson());
				boardVersion = saveBoardVersion(savedDashBoard);
			}
		} else {
			if (dashboardLimitReached(userName)) {
				response.setMessage(helper.message(INFO_DASHBOARD_LIMIT_REACHED));
				return ResponseEntity.status(HttpStatus.FORBIDDEN).body(response);
			}

			setDashBoardTitle(dashBoard, false);
			savedDashBoard = userDashBoardRepo.save(dashBoard);
			response.setBoardName(savedDashBoard.getId());
			response.setData(savedDashBoard.getJson());
			boardVersion = saveBoardVersion(savedDashBoard);

		}
		picService.createPreviewImage(boardVersion.getId(), getShareId(savedDashBoard.getId()));
		response.setMessage(helper.message(INFO_USER_SAVE_DASHBOARD_DATA));
		response.setStatus(true);
		return ResponseEntity.status(HttpStatus.OK).body(response);
	}

	public ResponseEntity<UserListResponse> getUserList(String searchString) {
		UserListResponse response = new UserListResponse();

		List<User> listOfUsers = userRepo.findByUserNameContainingIgnoreCaseOrFullNameContainingIgnoreCase(searchString,
				searchString);

		if (listOfUsers.isEmpty()) {
			response.setListOfUsers(Collections.emptyList());
			response.setMessage("users not found");
			response.setStatus(false);
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
		}

		List<String> listOfEmails = new ArrayList<String>();
		for (User usr : listOfUsers) {
			if (!listOfEmails.contains(usr.getUserName()))
				listOfEmails.add(usr.getUserName());

		}
		response.setListOfUsers(listOfEmails);
		response.setStatus(true);
		response.setMessage("users found");
		return ResponseEntity.status(HttpStatus.OK).body(response);

	}

	public ResponseEntity<RestResponse> userCleanup(String username) {
		username = username.toLowerCase();
		Optional<User> userRecord = userRepo.findFirstByUserName(username);
		User user = userRecord.orElse(null);
		RestResponse response = new RestResponse();

		if (user == null) {
			response.setStatus(false);
			response.setMessage(helper.message(ERROR_USER_NOT_FOUND));
			return ResponseEntity.status(HttpStatus.NOT_FOUND).body(response);
		}

		deleteDashboard(user.getUserName());
		deleteUsrActivity(username);
		userRepo.delete(user);
		response.setMessage(helper.message(SUCCESS_CLEANUP_MESSAGE));
		response.setStatus(true);
		return ResponseEntity.status(HttpStatus.OK).body(response);

	}

	private void deleteDashboard(String username) {
		List<UserDashBoard> listOfDashBoard = userDashBoardRepo.findByUserName(username);
		for (UserDashBoard board : listOfDashBoard) {
			deleteBoardVersions(board.getId());
			deleteBoardShare(board.getId());
			userDashBoardRepo.delete(board);
		}
	}

	private void deleteBoardVersions(String boardName) {
		List<DashBoardVersion> listOfVersion = boardVersionRepo.findByBoardName(boardName);
		for (DashBoardVersion version : listOfVersion) {
			deletePreviewImage(version.getId());
		}
		boardVersionRepo.deleteByBoardName(boardName);
	}

	private void deletePreviewImage(String versionID) {
		String fileName = versionID + "." + previewImageFormat;
		String imagePath = helper.imagePath + helper.imageDir + "/" + fileName;
		try {
			File file = new File(imagePath);
			if (!file.delete()) {
				log.error(helper.message(ERROR_DELETE_FILE));
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	private void deleteBoardShare(String boardName) {
		boardShareRepo.deleteByBoardName(boardName);
	}

	private void deleteUsrActivity(String username) {
		List<UserActivity> listUsrActivity = usrActivityRepo.findByUsername(username);
		for (UserActivity usrActivity : listUsrActivity) {
			deleteUsrActivityContent(usrActivity.getId());
			// usrActivityRepo.delete(usrActivity);
		}
		usrActivityRepo.deleteByUsername(username);
	}

	private void deleteUsrActivityContent(String activityID) {
		usrActivityContentRepo.deleteByActivityId(activityID);
	}

	private UserDashBoard setBoardProperties(UserDashBoard dashBoard, UserDashBoard boardPropToSet) {
		boardPropToSet.setJson(dashBoard.getJson());
		boardPropToSet.setPreviewImage(dashBoard.getPreviewImage());
		boardPropToSet.setBoardMessage(dashBoard.getBoardMessage());
		boardPropToSet.setTitle(dashBoard.getTitle());
		boardPropToSet.setGoldenNugget(dashBoard.isGoldenNugget());
		setDashBoardTitle(boardPropToSet, true);
		return userDashBoardRepo.save(boardPropToSet);
	}

	private boolean dashboardLimitReached(String username) {
		int boardInDatabase = getNumOfCanvasForUser(username);
		int boardLimit = Integer.parseInt(dashboardLimit);
		return (boardLimit > 0 && boardLimit <= boardInDatabase);
	}

	private int getNumOfCanvasForUser(String user) {
		return userDashBoardRepo.countByUserNameAndArchiveIsFalse(user);
	}

	private void setDashBoardTitle(UserDashBoard board, boolean update) {

		String message;
		int size = getNumOfCanvasForUser(board.getUserName());
		if (update) {
			message = String.format(messageTitle, String.valueOf(size));
		} else {
			message = String.format(messageTitle, String.valueOf(size + 1));
		}
		if (board.getTitle() == null || board.getTitle().isEmpty()) {
//			String message;
//			int size = getNumOfCanvasForUser(board.getUserName());
//			if (update) {
//				message = String.format(messageTitle, String.valueOf(size));
//			} else {
//				message = String.format(messageTitle, String.valueOf(size + 1));
//			}
			board.setTitle(message);
			board.setAutoTitle(true);
		} else {
			if (message.equals(board.getTitle())) {
				board.setAutoTitle(true);
			} else {
				board.setAutoTitle(false);
			}
		}
	}

	private JSONArray listIntoJsonDashboard(List<UserDashBoard> dashboardList) {
		int index = 1;

		JSONArray boardList = new JSONArray();
		for (UserDashBoard board : dashboardList) {

			if (!board.isArchive()) {

				JSONObject object = new JSONObject();
				object.put(DASHBOARD_BOARDNAME, board.getId());
				object.put(DASHBOARD_PREVIEW_IMAGE_URL, helper.hostname + board.getPreviewImageUrl());
				object.put(PROPERTY_TITLE, board.getTitle());
				object.put(PROPERTY_DASHBOARD_AUTOTITLE, board.isAutoTitle());

				if (index == 1) {
					object.put(DASHBOARD_DEFAULT, true);
				}
				boardList.put(object);
				index++;
			}
		}
		return boardList;
	}

	private JSONArray listIntoJsonBoardVersion(List<DashBoardVersion> dashboardList) {
		JSONArray boardList = new JSONArray();
		for (DashBoardVersion board : dashboardList) {
			if (!board.isArchive()) {
				JSONObject object = new JSONObject();

				object.put(DASHBOARD_VERSION_ID, board.getId());
				object.put(DASHBOARD_PREVIEW_IMAGE_URL, helper.hostname + board.getPreviewImageUrl());
				object.put(DASHBOARD_VERSION_CREATED_DATE, helper.getDateTime(board.getCreatedDate()));
				object.put(PROPERTY_GOLDEN_NUGGET, board.isGoldenNugget());
				boardList.put(object);
			}
		}
		return boardList;

	}

	private DashBoardVersion saveBoardVersion(UserDashBoard board) {

		DashBoardVersion boardVersion = new DashBoardVersion();
		boardVersion.setJson(board.getJson());
		boardVersion.setPreviewImage(board.getPreviewImage());
		boardVersion.setBoardMessage(board.getBoardMessage());
		boardVersion.setTitle(board.getTitle());
		boardVersion.setUserName(board.getUserName());
		boardVersion.setGoldenNugget(board.isGoldenNugget());
		boardVersion.setBoardName(board.getId());
		return boardVersionRepo.save(boardVersion);
	}

	private String getShareId(String boardName) {
		BoardShare share = new BoardShare();
		share.setBoardName(boardName);
		BoardShareResponse response = getShareIdByCanvas(share).getBody();
		return response.getShareId();
	}

//	private String getVersionHaveImageFormed(UserDashBoard board) {
//		String boardID = board.getId();
//		List<DashBoardVersion> versionListByID = boardVersionRepo.findByBoardNameAndPreviewImageUrlNot(boardID, "");
//		
//		if(versionListByID.isEmpty()) {
//			return "";
//		}
//		return versionListByID.get(0).getPreviewImageUrl();
//	}

	private String getVersionHaveImageFormed(UserDashBoard board) {
		String boardID = board.getId();
		DashBoardVersion versionListByID = boardVersionRepo
				.findTopOneByBoardNameAndPreviewImageUrlNotOrderByLastModifiedDateDesc(boardID, "");

		if (versionListByID == null) {
			return "";
		}
		return versionListByID.getPreviewImageUrl();
	}

	private List<String> getRoleListByUser(User user) {

		if (user.getRoles() == null || user.getRoles().isEmpty()) {
			return Collections.emptyList();
		} else {
			return Arrays.asList(user.getRoles().split(","));

		}
	}

	private boolean isNewUser(String username) {

		int count = userDashBoardRepo.countByUserName(username);

		if (count == 0) {
			return true;
		}

		return false;
	}

	public List<User> findByActiveIsFalse() {
	return userRepo.findByActiveIsFalse();
		
		
		
	}

	 
	
}

